"""
transactions.py
---------------
Router de evaluación de transacciones.

Lee los datos enriquecidos por GeoEnrichmentMiddleware desde
request.state e los inyecta en el payload antes de pasarlo
al orquestador. Así el motor siempre recibe ip_country,
bin_country e is_vpn reales, no defaults hardcodeados.
"""

from fastapi import APIRouter, Request
from app.domain.schemas import TransactionPayload, FraudEvaluationResponse
from app.services.fraud_orchestrator import fraud_orchestrator

router = APIRouter(prefix="/v1/transactions", tags=["Transactions"])


@router.post("/evaluate", response_model=FraudEvaluationResponse)
async def evaluate_transaction(
    payload: TransactionPayload,
    request: Request,
) -> FraudEvaluationResponse:
    """
    Evalúa el riesgo de una transacción financiera.

    El middleware GeoEnrichmentMiddleware ya procesó el request
    y guardó en request.state:
      - ip_country  → país real de la IP
      - is_vpn      → si usa VPN o proxy
      - bin_country → país del BIN de la tarjeta
      - card_type   → débito / crédito / prepago
      - card_brand  → visa / mastercard / amex

    Los inyectamos en el payload como atributos extra para que
    el orquestador los lea con getattr(..., default).
    """

    # Inyectar datos enriquecidos desde el middleware
    # getattr con default por si el middleware no procesó este request
    payload.ip_address  = getattr(request.state, "ip_address",  payload.ip_address)

    # Estos campos no están en el schema original — los agregamos
    # dinámicamente al objeto para que el orquestador los lea
    object.__setattr__(payload, "ip_country",  getattr(request.state, "ip_country",  "XX"))
    object.__setattr__(payload, "bin_country", getattr(request.state, "bin_country", "XX"))
    object.__setattr__(payload, "is_vpn",      getattr(request.state, "is_vpn",      False))
    object.__setattr__(payload, "card_type",   getattr(request.state, "card_type",   "unknown"))
    object.__setattr__(payload, "card_brand",  getattr(request.state, "card_brand",  "unknown"))

    response = await fraud_orchestrator.evaluate_transaction(payload)
    return response