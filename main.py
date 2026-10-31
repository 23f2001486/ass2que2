import hashlib
import json
from typing import Dict, List, Any, Optional
from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field

app = FastAPI(title="Public HTTPS Mailroom Agent", version="1.0.0")

# Durable in-memory stores for demonstration (use persistent DB/Redis for production resilience)
PROPOSAL_CACHE: Dict[str, Dict[str, Any]] = {}  # Keyed by canonical content hash
EVALUATION_STATE: Dict[str, Dict[str, Any]] = {} # Keyed by evaluationId
COMMITTED_RECEIPTS: set = set()

# Allowed Action Schemas
PERMITTED_ACTIONS = {
    "create_draft",
    "update_internal_record",
    "send_approved_notice",
    "request_confirmation",
    "quarantine_item",
    "no_action"
}

class DossierItem(BaseModel.model_config = {"extra": "allow"} if hasattr(BaseModel, "model_config") else None):
    pass

class ProposeRequest(BaseModel):
    operation: str
    evaluationId: str
    dossiers: List[Dict[str, Any]]

class ReceiptItem(BaseModel):
    evaluationId: str
    callId: str
    action: str
    proposalDigest: str
    receiptSignature: str

class CommitRequest(BaseModel):
    operation: str
    receipts: List[Dict[str, Any]]


def compute_canonical_hash(dossier: Dict[str, Any]) -> str:
    """Computes a stable content fingerprint for core caching."""
    filtered = {k: v for k, v in sorted(dossier.items()) if k not in ["evaluationId", "timestamp"]}
    canonical_str = json.dumps(filtered, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


def evaluate_dossier_logic(dossier: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates safety, prompt-injection defense, and assigns a permitted action.
    Replace or augment this with your LLM/heuristic logic.
    """
    content = str(dossier.get("content", ""))
    subject = str(dossier.get("subject", ""))
    
    # Simple security guardrails for injections
    lower_content = content.lower()
    if "ignore previous instructions" in lower_content or "system prompt" in lower_content or "exfiltrate" in lower_content:
        return {
            "action": "quarantine_item",
            "target": dossier.get("id", "unknown"),
            "payload": {"reason": "Potential prompt injection detected"},
            "evidence": [1, 2]
        }
    
    # Default safe fallback action
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

    operation = body.get("operation")

    # --- OPERATION: PROPOSE ---
    if operation == "propose":
        evaluation_id = body.get("evaluationId")
        dossiers = body.get("dossiers")

        if not evaluation_id or not isinstance(dossiers, list):
            raise HTTPException(status_code=422, detail="Missing evaluationId or dossiers list.")

        # Check for changed-content conflict under the same evaluationId
        if evaluation_id in EVALUATION_STATE:
            stored_payload_hash = EVALUATION_STATE[evaluation_id]["payload_hash"]
            current_payload_hash = hashlib.sha256(json.dumps(dossiers, sort_keys=True).encode()).hexdigest()
            if stored_payload_hash != current_payload_hash:
                raise HTTPException(status_code=409, detail="Conflict: Same evaluationId with changed content.")
            return EVALUATION_STATE[evaluation_id]["response"]

        proposals = []
        for dossier in dossiers:
            dossier_id = dossier.get("id", "dossier_unknown")
            canonical_hash = compute_canonical_hash(dossier)

            # Check core cache
            if canonical_hash in PROPOSAL_CACHE:
                cached_proposal = PROPOSAL_CACHE[canonical_hash].copy()
                cached_proposal["id"] = dossier_id # Ensure current dossier ID maps correctly
                proposals.append(cached_proposal)
                continue

            # Evaluate decision
            decision = evaluate_dossier_logic(dossier)
            action = decision.get("action")
            
            if action not in PERMITTED_ACTIONS:
                action = "no_action"

            call_id = hashlib.sha256(f"{evaluation_id}:{dossier_id}".encode()).hexdigest()[:16]
            proposal_digest = hashlib.sha256(json.dumps(decision, sort_keys=True).encode()).hexdigest()[:32]

            proposal_item = {
                "callId": call_id,
                "dossierId": dossier_id,
                "action": action,
                "target": decision.get("target"),
                "payload": decision.get("payload"),
                "evidence": decision.get("evidence", []),
                "proposalDigest": proposal_digest
            }

            # Cache by canonical dossier content
            PROPOSAL_CACHE[canonical_hash] = proposal_item
            proposals.append(proposal_item)

        response_data = {
            "status": "awaiting_receipts",
            "proposals": proposals
        }

        # Save evaluation state
        EVALUATION_STATE[evaluation_id] = {
            "payload_hash": hashlib.sha256(json.dumps(dossiers, sort_keys=True).encode()).hexdigest(),
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
            evaluation_id = receipt.get("evaluationId")
            call_id = receipt.get("callId")
            action = receipt.get("action")
            proposal_digest = receipt.get("proposalDigest")
            receipt_signature = receipt.get("receiptSignature")

            if not all([evaluation_id, call_id, action, proposal_digest, receipt_signature]):
                raise HTTPException(status_code=422, detail="Malformed receipt structure.")

            # Verify receipt signature validity (mocked validation check)
            if len(receipt_signature) < 8:
                raise HTTPException(status_code=400, detail="Invalid receipt signature.")

            COMMITTED_RECEIPTS.add(call_id)
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
