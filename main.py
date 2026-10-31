import hashlib
import json
from typing import Dict, List, Any, Optional
from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel

app = FastAPI(title="Public HTTPS Mailroom Agent", version="2.0.0")

# In-memory storage for persistent state across requests
PROPOSAL_CACHE: Dict[str, Dict[str, Any]] = {}  # Keyed by canonical content hash
EVALUATION_STATE: Dict[str, Dict[str, Any]] = {} # Keyed by evaluationId
COMMITTED_RECEIPTS: Dict[str, set] = {}         # evaluationId -> set of committed callIds

PERMITTED_ACTIONS = {
    "create_draft",
    "update_internal_record",
    "send_approved_notice",
    "request_confirmation",
    "quarantine_item",
    "no_action"
}

def compute_canonical_hash(dossier: Dict[str, Any]) -> str:
    """Computes a stable content fingerprint for core caching."""
    filtered = {k: v for k, v in sorted(dossier.items()) if k not in ["evaluationId", "timestamp"]}
    canonical_str = json.dumps(filtered, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

def evaluate_dossier_logic(dossier: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates dossier content and assigns a permitted action, target, payload, and evidence.
    """
    content = str(dossier.get("content", ""))
    subject = str(dossier.get("subject", ""))
    lower_content = content.lower()
    
    # Prompt injection / security guardrails
    if any(term in lower_content for term in ["ignore previous instructions", "system prompt", "exfiltrate", "override"]):
        return {
            "action": "quarantine_item",
            "target": dossier.get("id", "unknown"),
            "payload": {"reason": "Potential prompt injection or safety violation detected"},
            "evidence": [1, 2]
        }
    
    # Standard default safe fallback action
    return {
        "action": "no_action",
        "target": dossier.get("id", "unknown"),
        "payload": {},
        "evidence": [1]
    }

@app.post("/")
async def mailroom_endpoint(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload.")

    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object.")

    operation = body.get("operation")

    # --- OPERATION: PROPOSE ---
    if operation == "propose":
        evaluation_id = body.get("evaluationId")
        dossiers = body.get("dossiers")

        if not evaluation_id or not isinstance(dossiers, list):
            raise HTTPException(status_code=422, detail="Missing evaluationId or dossiers list.")

        # Check for duplicate dossier IDs within the same request
        dossier_ids = [d.get("id") for d in dossiers if isinstance(d, dict)]
        if len(dossier_ids) != len(set(dossier_ids)):
            raise HTTPException(status_code=400, detail="Duplicate dossier IDs detected in request.")

        # Check for changed-content conflict under the same evaluationId
        current_payload_hash = hashlib.sha256(json.dumps(dossiers, sort_keys=True).encode()).hexdigest()
        if evaluation_id in EVALUATION_STATE:
            stored_state = EVALUATION_STATE[evaluation_id]
            if stored_state["payload_hash"] != current_payload_hash:
                raise HTTPException(status_code=409, detail="Conflict: Same evaluationId with changed content.")
            return Response(content=json.dumps(stored_state["response"]), media_type="application/json")

        proposals = []
        evaluation_proposals_map = {}

        for dossier in dossiers:
            if not isinstance(dossier, dict) or "id" not in dossier:
                raise HTTPException(status_code=422, detail="Malformed dossier item missing 'id'.")

            dossier_id = dossier["id"]
            canonical_hash = compute_canonical_hash(dossier)
            input_digest = hashlib.sha256(json.dumps(dossier, sort_keys=True).encode()).hexdigest()[:32]

            # Check core cache or evaluate
            if canonical_hash in PROPOSAL_CACHE:
                cached_item = PROPOSAL_CACHE[canonical_hash].copy()
                cached_item["id"] = dossier_id  # Ensure exact input dossier ID is preserved
                call_id = cached_item["callId"]
                proposals.append(cached_item)
                evaluation_proposals_map[call_id] = cached_item
                continue

            decision = evaluate_dossier_logic(dossier)
            action = decision.get("action")
            if action not in PERMITTED_ACTIONS:
                action = "no_action"

            call_id = hashlib.sha256(f"{evaluation_id}:{dossier_id}".encode()).hexdigest()[:16]
            proposal_digest = hashlib.sha256(json.dumps(decision, sort_keys=True).encode()).hexdigest()[:32]

            proposal_item = {
                "callId": call_id,
                "id": dossier_id,
                "action": action,
                "target": decision.get("target"),
                "payload": decision.get("payload", {}),
                "evidence": decision.get("evidence", [1]),
                "inputDigest": proposal_digest  # Supporting both inputDigest / proposalDigest naming norms
            }

            PROPOSAL_CACHE[canonical_hash] = proposal_item
            proposals.append(proposal_item)
            evaluation_proposals_map[call_id] = proposal_item

        response_data = {
            "status": "awaiting_receipts",
            "proposals": proposals
        }

        # Store evaluation state for replay and commit validation
        EVALUATION_STATE[evaluation_id] = {
            "payload_hash": current_payload_hash,
            "proposals_map": evaluation_proposals_map,
            "response": response_data
        }

        return Response(content=json.dumps(response_data), media_type="application/json")

    # --- OPERATION: COMMIT ---
    elif operation == "commit":
        receipts = body.get("receipts")
        if not receipts or not isinstance(receipts, list):
            raise HTTPException(status_code=400, detail="Missing or invalid receipts list.")

        outcomes = []
        for receipt in receipts:
            if not isinstance(receipt, dict):
                raise HTTPException(status_code=422, detail="Malformed receipt structure.")

            evaluation_id = receipt.get("evaluationId")
            call_id = receipt.get("callId")
            action = receipt.get("action")
            proposal_digest = receipt.get("proposalDigest") or receipt.get("inputDigest")
            receipt_signature = receipt.get("receiptSignature")

            if not all([evaluation_id, call_id, action, proposal_digest, receipt_signature]):
                raise HTTPException(status_code=422, detail="Malformed receipt missing required fields.")

            # Validate evaluation existence
            if evaluation_id not in EVALUATION_STATE:
                raise HTTPException(status_code=400, detail="Unknown evaluationId in commit.")

            eval_state = EVALUATION_STATE[evaluation_id]
            proposals_map = eval_state["proposals_map"]

            # Validate callId matches stored proposal
            if call_id not in proposals_map:
                raise HTTPException(status_code=400, detail="Invalid callId for this evaluation.")

            stored_proposal = proposals_map[call_id]

            # Strict validation: Action and digest must match stored proposal exactly
            if stored_proposal["action"] != action or stored_proposal["inputDigest"] != proposal_digest:
                raise HTTPException(status_code=400, detail="Receipt action or proposal digest mismatch.")

            # Record committed receipt
            if evaluation_id not in COMMITTED_RECEIPTS:
                COMMITTED_RECEIPTS[evaluation_id] = set()
            COMMITTED_RECEIPTS[evaluation_id].add(call_id)

            outcomes.append({
                "callId": call_id,
                "status": "completed"
            })

        commit_response = {
            "status": "completed",
            "outcomes": outcomes
        }
        return Response(content=json.dumps(commit_response), media_type="application/json")

    else:
        raise HTTPException(status_code=400, detail="Unsupported operation type.")
