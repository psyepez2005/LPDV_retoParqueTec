import asyncio
import time
import uuid
from typing import Tuple, List
from app.domain.schemas import TransactionPayload, FraudEvaluationResponse, ActionDecision, ChallengeType
from app.infrastructure.cache.redis_client import redis_manager
from app.services.topup_rules import TopUpRulesEngine

class FraudOrchestrator:
    W1_VELOCITY = 0.25
    W2_DEVICE = 0.20
    W3_GEO = 0.20
    W4_BEHAVIOR = 0.20
    W5_EXTERNAL = 0.15

    def __init__(self):
        self.topup_engine = TopUpRulesEngine()

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

        # Recopilacion de codigos de razon para auditoria
        if device_score >= 60: reason_codes.append("SUSPICIOUS_DEVICE_FINGERPRINT")
        if geo_score >= 60: reason_codes.append("GEO_MISMATCH_OR_HIGH_RISK_IP")
        if velocity_score >= 40: reason_codes.append("HIGH_VELOCITY_OR_LIMIT_EXCEEDED")

        action, challenge, user_msg = self._determine_action(risk_score)

        processing_time_ms = int((time.perf_counter() - start_time) * 1000)

        return FraudEvaluationResponse(
            transaction_id=evaluation_id,
            action=action,
            risk_score=risk_score,
            challenge_type=challenge,
            reason_codes=reason_codes,
            user_message=user_msg,
            response_time_ms=processing_time_ms,
            signature="0" * 64
        )

    async def _evaluate_kyc_device(self, payload: TransactionPayload) -> float:
        await asyncio.sleep(0.02)
        score = 0.0     
        user_agent_lower = payload.user_agent.lower()
        
        # Deteccion basica de emuladores y automatizacion
        suspicious_keywords = ["bluestacks", "nox", "emulator", "headless", "selenium"]
        if any(keyword in user_agent_lower for keyword in suspicious_keywords):
            score += 80.0
            
        return min(score, 100.0)

    async def _query_external_api(self, payload: TransactionPayload) -> float:
        await asyncio.sleep(0.05)
        return 10.0 

    async def _evaluate_internal_rules(self, payload: TransactionPayload) -> Tuple[float, float, float]:
        await asyncio.sleep(0.03)
        # Se inyecta la conexion activa de Redis
        velocity_score = await self.topup_engine.evaluate(payload, redis_manager.client)
        
        geo_score = 0.0
        # Validacion de Geo-Mismatch: Si la coordenada lat/lon es exactamente 0.0, es un intento de ofuscacion de GPS
        if payload.latitude == 0.0 and payload.longitude == 0.0:
            geo_score += 50.0

        behavior_score = 10.0
        
        return (velocity_score, geo_score, behavior_score)

    def _determine_action(self, score: int) -> Tuple[ActionDecision, ChallengeType | None, str]:
        if 0 <= score <= 30:
            return ActionDecision.ACTION_APPROVE, None, "Transaccion aprobada."
        elif 31 <= score <= 60:
            return ActionDecision.ACTION_CHALLENGE_SOFT, ChallengeType.SMS_OTP, "Verificacion requerida."
        elif 61 <= score <= 75:
            return ActionDecision.ACTION_CHALLENGE_HARD, ChallengeType.THREEDS, "Verificacion adicional requerida."
        elif 76 <= score <= 90:
            return ActionDecision.ACTION_BLOCK_REVIEW, None, "Transaccion en revision."
        else:
            return ActionDecision.ACTION_BLOCK_PERM, None, "Operacion declinada por politicas de seguridad."

fraud_orchestrator = FraudOrchestrator()