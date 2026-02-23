import asyncio
import time
import uuid
from typing import Tuple, List
from app.domain.schemas import TransactionPayload, FraudEvaluationResponse, ActionDecision, ChallengeType

class FraudOrchestrator:
    W1_VELOCITY = 0.25
    W2_DEVICE = 0.20
    W3_GEO = 0.20
    W4_BEHAVIOR = 0.20
    W5_EXTERNAL = 0.15

    async def evaluate_transaction(self, payload: TransactionPayload) -> FraudEvaluationResponse:
        start_time = time.perf_counter()
        evaluation_id = uuid.uuid4()
        reason_codes = []

        kyc_task = self._evaluate_kyc_device(payload)
        ext_api_task = self._query_external_api(payload)
        internal_rules_task = self._evaluate_internal_rules(payload)

        device_score, ext_score, rules_scores = await asyncio.gather(
            kyc_task, ext_api_task, internal_rules_task
        )

        velocity_score, geo_score, behavior_score = rules_scores

        risk_score = int(
            (self.W1_VELOCITY * velocity_score) +
            (self.W2_DEVICE * device_score) +
            (self.W3_GEO * geo_score) +
            (self.W4_BEHAVIOR * behavior_score) +
            (self.W5_EXTERNAL * ext_score)
        )

        action, challenge, user_msg = self._determine_action(risk_score)

        if risk_score > 30:
            reason_codes.append("ELEVATED_RISK_SCORE")

        processing_time_ms = int((time.perf_counter() - start_time) * 1000)

        return FraudEvaluationResponse(
            transaction_id=evaluation_id,
            action=action,
            risk_score=risk_score,
            challenge_type=challenge,
            reason_codes=reason_codes,
            user_message=user_msg,
            response_time_ms=processing_time_ms,
            signature="placeholder_hmac_signature"
        )

    async def _evaluate_kyc_device(self, payload: TransactionPayload) -> float:
        await asyncio.sleep(0.02)
        return 10.0

    async def _query_external_api(self, payload: TransactionPayload) -> float:
        await asyncio.sleep(0.05)
        return 15.0

    async def _evaluate_internal_rules(self, payload: TransactionPayload) -> Tuple[float, float, float]:
        await asyncio.sleep(0.03)
        return (5.0, 20.0, 10.0)

    def _determine_action(self, score: int) -> Tuple[ActionDecision, ChallengeType | None, str]:
        if 0 <= score <= 30:
            return ActionDecision.ACTION_APPROVE, None, "Transaccion aprobada."
        elif 31 <= score <= 60:
            return ActionDecision.ACTION_CHALLENGE_SOFT, ChallengeType.SMS_OTP, "Por tu seguridad, necesitamos verificar tu identidad."
        elif 61 <= score <= 75:
            return ActionDecision.ACTION_CHALLENGE_HARD, ChallengeType.THREEDS, "Verificacion adicional requerida por su banco."
        elif 76 <= score <= 90:
            return ActionDecision.ACTION_BLOCK_REVIEW, None, "Transaccion en revision. Un analista revisara su caso pronto."
        else:
            return ActionDecision.ACTION_BLOCK_PERM, None, "Operacion declinada por politicas de seguridad."

fraud_orchestrator = FraudOrchestrator()