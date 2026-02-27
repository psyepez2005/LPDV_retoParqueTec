
from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_db_session
from app.domain.schemas import TransactionPayload, FraudEvaluationResponse, EncryptedPayload, PublicKeyResponse
from app.services.fraud_orchestrator import fraud_orchestrator
from app.core import crypto

from app.api.deps import get_current_user 
router = APIRouter(prefix="/v1/transactions", tags=["Transactions"])

@router.get("/public-key", response_model=PublicKeyResponse)
async def get_public_key():
    """Returns the RSA Public Key for frontend E2E Encryption."""
    try:
        return PublicKeyResponse(public_key=crypto.get_public_key_pem())
    except Exception as e:
        raise HTTPException(status_code=500, detail="Public key not configured.")

@router.post("/evaluate", response_model=FraudEvaluationResponse)
async def evaluate_transaction(
    encrypted_payload: EncryptedPayload,
    request: Request,
    db: AsyncSession = Depends(get_db_session),

    current_user_id: str = Depends(get_current_user),

    # _verified_payload: dict = Depends(validate_hmac   _integrity)
) -> FraudEvaluationResponse:

    # 1. Decrypt E2E payload
    try:
        raw_dict = crypto.decrypt_payload(
            encrypted_aes_key_b64=encrypted_payload.encrypted_aes_key,
            iv_b64=encrypted_payload.iv,
            ciphertext_b64=encrypted_payload.ciphertext,
            auth_tag_b64=encrypted_payload.auth_tag
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Decryption error.")

    # 2. Parse into Pydantic model
    try:
        payload = TransactionPayload(**raw_dict)
    except Exception as e:
        # Give a 422 if the JSON structure is wrong inside the ciphertext
        raise HTTPException(status_code=422, detail="Valid encryption but invalid JSON payload schema.")

    payload.ip_address = getattr(request.state, "ip_address", getattr(payload, "ip_address", "0.0.0.0"))

    object.__setattr__(payload, "ip_country",  getattr(request.state, "ip_country",  "XX"))
    object.__setattr__(payload, "bin_country", getattr(request.state, "bin_country", "XX"))
    object.__setattr__(payload, "is_vpn",      getattr(request.state, "is_vpn",      False))
    object.__setattr__(payload, "card_type",   getattr(request.state, "card_type",   "unknown"))
    object.__setattr__(payload, "card_brand",  getattr(request.state, "card_brand",  "unknown"))

    response = await fraud_orchestrator.evaluate_transaction(payload, db=db)
    
    return response