from fastapi import APIRouter
from app.domain.schemas import TransactionPayload, FraudEvaluationResponse
from app.services.rules_engine import fraud_orchestrator

router = APIRouter(prefix="/v1/transactions", tags=["Transactions"])

@router.post("/evaluate", response_model=FraudEvaluationResponse)
async def evaluate_transaction(payload: TransactionPayload):
    response = await fraud_orchestrator.evaluate_transaction(payload)
    return response