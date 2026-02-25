
from fastapi import APIRouter, Request
from app.domain.schemas import TransactionPayload, FraudEvaluationResponse
from app.services.fraud_orchestrator import fraud_orchestrator

router = APIRouter(prefix="/v1/transactions", tags=["Transactions"])


@router.post("/evaluate", response_model=FraudEvaluationResponse)
async def evaluate_transaction(
    payload: TransactionPayload,
    request: Request,
) -> FraudEvaluationResponse:


    payload.ip_address  = getattr(request.state, "ip_address",  payload.ip_address)

    object.__setattr__(payload, "ip_country",  getattr(request.state, "ip_country",  "XX"))
    object.__setattr__(payload, "bin_country", getattr(request.state, "bin_country", "XX"))
    object.__setattr__(payload, "is_vpn",      getattr(request.state, "is_vpn",      False))
    object.__setattr__(payload, "card_type",   getattr(request.state, "card_type",   "unknown"))
    object.__setattr__(payload, "card_brand",  getattr(request.state, "card_brand",  "unknown"))

    response = await fraud_orchestrator.evaluate_transaction(payload)
    return response