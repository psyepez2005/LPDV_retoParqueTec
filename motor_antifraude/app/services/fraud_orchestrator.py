"""
fraud_orchestrator.py
---------------------
Orquestador principal del Motor Antifraude — Wallet Plux.

Coordina todos los módulos de análisis y produce una decisión accionable
en < 200ms (P99). No contiene lógica de detección propia — delega en
los módulos especializados y agrega sus resultados.

Flujo de ejecución:
  1. Blacklist check          →  1-3ms    corto circuito inmediato si hay hit
  2. asyncio.gather paralelo  →  ~120ms   todos los módulos simultáneamente
       ├─ _evaluate_kyc_device            device fingerprint + multi-cuenta
       ├─ _query_external_api             Sift/Kount con timeout 80ms + fallback
       ├─ _evaluate_velocity              TopUpRulesEngine via Redis
       ├─ GeoAnalyzer.analyze             viaje imposible + Modo Viajero
       ├─ BehaviorEngine.analyze          patrón conductual + account takeover
       ├─ TrustScoreService.get_profile   reducción por historial
       └─ P2PAnalyzer.analyze             solo si transaction_type == P2P_SEND
  3. Risk Score ponderado     →  < 1ms    W1·V + W2·D + W3·G + W4·B + W5·E
  4. Trust reduction          →  < 1ms    hasta -25 pts para usuarios legítimos
  5. P2P penalty              →  < 1ms    penalización adicional si aplica
  6. Overrides críticos       →  < 1ms    viaje imposible, mula confirmada
  7. Decision engine          →  < 1ms    APPROVE / CHALLENGE / BLOCK
  8. HMAC-SHA256              →  1-2ms    firma de la respuesta
  9. Background tasks         →  async    fire-and-forget, no bloquea respuesta

Compatibilidad:
  - Reemplaza directamente el fraud_orchestrator.py original
  - El singleton fraud_orchestrator al final del archivo mantiene
    la misma interfaz: await fraud_orchestrator.evaluate_transaction(payload)
  - topup_rules.py, redis_client.py, schemas y routers NO se modifican
"""

import asyncio
import hashlib
import hmac as hmac_lib
import json
import logging
import os
import time
import uuid
from typing import Optional, Tuple

from app.domain.schemas import (
    TransactionPayload,
    FraudEvaluationResponse,
    ActionDecision,
    ChallengeType,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.cache.redis_client import redis_manager
from app.infrastructure.database.audit_repository import AuditRepository
from app.services.topup_rules import TopUpRulesEngine
from app.services.blacklist_service import BlacklistService, BlacklistType
from app.services.trust_score import TrustScoreService
from app.services.geo_analyzer import GeoAnalyzer
from app.services.behavior_engine import BehaviorEngine
from app.services.p2p_analyzer import P2PAnalyzer

logger = logging.getLogger(__name__)

# ── Clave HMAC ────────────────────────────────────────────────────────
# En producción cargar desde KMS o secret manager, nunca hardcodeada.
# La variable de entorno FRAUD_HMAC_SECRET debe estar cifrada en el
# sistema de secretos (AWS Secrets Manager, Vault, etc.)
_HMAC_SECRET: bytes = os.environ.get(
    "FRAUD_HMAC_SECRET",
    "dev-secret-replace-in-production",
).encode()


class FraudOrchestrator:
    """
    Orquestador principal del motor antifraude.

    Pesos del modelo de scoring (deben sumar exactamente 1.0):
      W1 Velocity  = 0.25  — velocidad y límites de recarga
      W2 Device    = 0.20  — fingerprint, emuladores, multi-cuenta
      W3 Geo       = 0.20  — geolocalización, viaje imposible
      W4 Behavior  = 0.20  — patrón conductual, account takeover
      W5 External  = 0.15  — score de Sift/Kount

    Los pesos son atributos de clase para poder modificarlos en caliente
    desde el panel de administración sin redespliegue:
      FraudOrchestrator.W1_VELOCITY = 0.30
    """

    W1_VELOCITY = 0.25
    W2_DEVICE   = 0.20
    W3_GEO      = 0.20
    W4_BEHAVIOR = 0.20
    W5_EXTERNAL = 0.15

    def __init__(self):
        redis = redis_manager.client
        self.topup_engine    = TopUpRulesEngine()
        self.blacklist       = BlacklistService(redis)
        self.trust_service   = TrustScoreService(redis)
        self.geo_analyzer    = GeoAnalyzer(redis)
        self.behavior_engine = BehaviorEngine(redis)
        self.p2p_analyzer    = P2PAnalyzer(redis)

    # ------------------------------------------------------------------ #
    #  Entry point — misma firma que el orquestador original             #
    # ------------------------------------------------------------------ #

    async def evaluate_transaction(
        self,
        payload: TransactionPayload,
        db: Optional[AsyncSession] = None,
    ) -> FraudEvaluationResponse:
        """
        Evalúa una transacción y retorna una decisión accionable.
        Interfaz idéntica al orquestador original — compatible drop-in.
        """
        start_time    = time.perf_counter()
        evaluation_id = uuid.uuid4()
        reason_codes: list[str] = []

        # ══════════════════════════════════════════════════════════════
        # PASO 1 — Blacklist check
        # Corto circuito: si cualquier entidad está bloqueada respondemos
        # en < 5ms sin ejecutar ningún módulo de análisis.
        # ══════════════════════════════════════════════════════════════
        bl_hit = await self.blacklist.check(
            user_id    = str(payload.user_id),
            device_id  = payload.device_id,
            ip_address = payload.ip_address,
            card_bin   = payload.card_bin,
        )

        if bl_hit.hit:
            reason_codes.append(
                f"BLACKLIST_{bl_hit.blacklist_type.value.upper()}_HIT"
            )
            logger.warning(
                f"[Orchestrator] BLACKLIST HIT — "
                f"type={bl_hit.blacklist_type}  user={payload.user_id}  "
                f"reason={bl_hit.reason}"
            )
            processing_ms = int((time.perf_counter() - start_time) * 1000)
            return self._build_response(
                evaluation_id = evaluation_id,
                action        = ActionDecision.ACTION_BLOCK_PERM,
                risk_score    = 100,
                challenge     = None,
                reason_codes  = reason_codes,
                user_message  = "Operación declinada por políticas de seguridad.",
                processing_ms = processing_ms,
            )

        # ══════════════════════════════════════════════════════════════
        # PASO 2 — Análisis paralelo
        # Todos los módulos se ejecutan simultáneamente con gather.
        # El tiempo total es el del módulo más lento, no la suma.
        # ══════════════════════════════════════════════════════════════
        is_p2p = payload.transaction_type == "P2P_SEND"

        # Campos enriquecidos por el middleware de GeoIP antes de llegar aquí.
        # Si el middleware no los provee, usamos defaults seguros.
        ip_country  = getattr(payload, "ip_country",  "MX")
        bin_country = getattr(payload, "bin_country", "MX")
        is_vpn      = getattr(payload, "is_vpn",      False)

        # Construir lista de tareas base (siempre se ejecutan)
        tasks = [
            self._evaluate_kyc_device(payload),             # → float
            self._query_external_api(payload),              # → float
            self._evaluate_velocity(payload),               # → float
            self.geo_analyzer.analyze(                      # → GeoAnalysisResult
                user_id     = str(payload.user_id),
                latitude    = payload.latitude,
                longitude   = payload.longitude,
                ip_country  = ip_country,
                bin_country = bin_country,
                is_vpn      = is_vpn,
            ),
            self.behavior_engine.analyze(                   # → BehaviorAnalysisResult
                user_id          = str(payload.user_id),
                amount           = float(payload.amount),
                currency         = payload.currency,
                transaction_type = payload.transaction_type,
                recipient_id     = (
                    str(payload.recipient_id)
                    if is_p2p and payload.recipient_id
                    else None
                ),
            ),
            self.trust_service.get_trust_profile(           # → TrustProfile
                user_id      = str(payload.user_id),
                device_id    = payload.device_id,
                country_code = ip_country,
            ),
        ]

        # Tarea P2P: solo si es una transferencia entre personas
        if is_p2p and payload.recipient_id:
            tasks.append(
                self.p2p_analyzer.analyze(                  # → P2PAnalysisResult
                    sender_id    = str(payload.user_id),
                    recipient_id = str(payload.recipient_id),
                    amount       = float(payload.amount),
                    currency     = payload.currency,
                )
            )

        # Ejecutar todo en paralelo
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        # ── Desempaquetar con manejo de excepciones ───────────────────
        # Si un módulo falla no tumbamos toda la evaluación — usamos
        # el fallback definido para ese módulo.
        device_score    = self._safe_float(raw_results[0], "kyc_device",    30.0)
        ext_score       = self._safe_float(raw_results[1], "external_api",  15.0)
        velocity_score  = self._safe_float(raw_results[2], "velocity",      20.0)
        geo_result      = self._safe_result(raw_results[3], "geo")
        behavior_result = self._safe_result(raw_results[4], "behavior")
        trust_profile   = self._safe_result(raw_results[5], "trust")
        p2p_result      = (
            self._safe_result(raw_results[6], "p2p")
            if is_p2p and len(raw_results) > 6
            else None
        )

        geo_score       = geo_result.score      if geo_result      else 20.0
        behavior_score  = behavior_result.score if behavior_result else 10.0
        trust_reduction = trust_profile.trust_reduction if trust_profile else 0

        # ══════════════════════════════════════════════════════════════
        # PASO 3 — Calcular Risk Score ponderado
        # Fórmula: Risk = W1·V + W2·D + W3·G + W4·B + W5·E
        # ══════════════════════════════════════════════════════════════
        weighted_score = (
            (self.W1_VELOCITY * velocity_score)  +
            (self.W2_DEVICE   * device_score)    +
            (self.W3_GEO      * geo_score)        +
            (self.W4_BEHAVIOR * behavior_score)   +
            (self.W5_EXTERNAL * ext_score)
        )

        # P2P penalty: el score P2P aporta hasta 30% adicional al score base.
        # No va dentro de la fórmula ponderada porque P2P es opcional —
        # solo aplica a un subconjunto de transacciones.
        p2p_penalty = 0.0
        if p2p_result:
            p2p_penalty = p2p_result.score * 0.30

        # Aplicar Trust reduction (valor negativo → reduce el score)
        # Clampear entre 0 y 100
        final_score = int(
            max(0.0, min(100.0, weighted_score + p2p_penalty + trust_reduction))
        )

        # ══════════════════════════════════════════════════════════════
        # PASO 4 — Recopilar reason_codes para auditoría
        # ══════════════════════════════════════════════════════════════
        if device_score >= 80:
            reason_codes.append("EMULATOR_OR_ROOT_DETECTED")
        elif device_score >= 60:
            reason_codes.append("SUSPICIOUS_DEVICE_FINGERPRINT")

        if velocity_score >= 40:
            reason_codes.append("HIGH_VELOCITY_OR_LIMIT_EXCEEDED")

        if geo_result:
            reason_codes.extend(geo_result.reason_codes)

        if behavior_result:
            reason_codes.extend(behavior_result.reason_codes)

        if p2p_result:
            reason_codes.extend(p2p_result.reason_codes)

        if trust_profile and trust_profile.trust_reduction < -10:
            reason_codes.append(
                f"TRUST_REDUCTION_{abs(trust_profile.trust_reduction)}PTS"
            )

        # ══════════════════════════════════════════════════════════════
        # PASO 5 — Overrides críticos
        # Ciertos patrones son tan claros que forzamos el score
        # independientemente del cálculo ponderado.
        # ══════════════════════════════════════════════════════════════

        # Viaje imposible → siempre al menos BLOCK_REVIEW
        if geo_result and geo_result.impossible_travel_detected:
            final_score = max(final_score, 76)
            reason_codes.append("OVERRIDE_IMPOSSIBLE_TRAVEL")

        # Patrón de mula P2P confirmado → siempre BLOCK_PERM
        if p2p_result and p2p_result.mule_pattern_detected:
            final_score = max(final_score, 91)
            reason_codes.append("OVERRIDE_MULE_PATTERN_CONFIRMED")

        # ══════════════════════════════════════════════════════════════
        # PASO 6 — Determinar acción
        # ══════════════════════════════════════════════════════════════
        action, challenge, user_msg = self._determine_action(
            score      = final_score,
            p2p_result = p2p_result,
        )

        # ══════════════════════════════════════════════════════════════
        # PASO 7 — Construir y firmar la respuesta
        # ══════════════════════════════════════════════════════════════
        processing_ms = int((time.perf_counter() - start_time) * 1000)

        response = self._build_response(
            evaluation_id = evaluation_id,
            action        = action,
            risk_score    = final_score,
            challenge     = challenge,
            reason_codes  = reason_codes,
            user_message  = user_msg,
            processing_ms = processing_ms,
        )

        logger.info(
            f"[Orchestrator] DECISION — "
            f"user={payload.user_id}  "
            f"score={final_score}  "
            f"action={action.value}  "
            f"time={processing_ms}ms  "
            f"codes={reason_codes}"
        )

        # ══════════════════════════════════════════════════════════════
        # PASO 8 — Background updates (fire-and-forget)
        # Se ejecutan DESPUÉS de que la respuesta ya fue enviada al Wallet.
        # create_task garantiza que no bloquean la respuesta.
        # ══════════════════════════════════════════════════════════════
        asyncio.create_task(
            self._background_updates(
                payload     = payload,
                final_score = final_score,
                action      = action,
                p2p_result  = p2p_result,
                response    = response,
                db          = db,
            )
        )

        return response

    # ------------------------------------------------------------------ #
    #  Módulo KYC & Device                                               #
    # ------------------------------------------------------------------ #

    async def _evaluate_kyc_device(self, payload: TransactionPayload) -> float:
        """
        Evalúa el riesgo del dispositivo y el user-agent.
        Tiempo esperado: 5-15ms (Redis lookups).
        """
        score      = 0.0
        ua_lower   = payload.user_agent.lower()
        redis      = redis_manager.client

        # ── Detección de emuladores y herramientas de automatización ──
        emulator_keywords = [
            "bluestacks", "nox", "ldplayer", "memu", "genymotion",
            "android_x86", "emulator", "headless", "selenium",
            "puppeteer", "playwright", "phantomjs", "webdriver",
        ]
        if any(kw in ua_lower for kw in emulator_keywords):
            return 90.0   # Retorno inmediato — emulador confirmado

        # ── User-agent inválido o demasiado corto ─────────────────────
        if not payload.user_agent or len(payload.user_agent) < 10:
            score += 35.0

        # ── Inconsistencia OS en user-agent vs sdk_version ────────────
        # ej. "iphone" en UA pero sdk_version empieza por "android"
        if "iphone" in ua_lower and payload.sdk_version.lower().startswith("android"):
            score += 45.0
        elif "android" in ua_lower and payload.sdk_version.lower().startswith("ios"):
            score += 45.0

        # ── Verificaciones en Redis ───────────────────────────────────
        try:
            known_key      = f"device:user:{payload.user_id}:known_devices"
            multi_acct_key = f"device:{payload.device_id}:users_24h"
            cards_key      = f"device:{payload.device_id}:cards_10min"

            is_known, user_count, card_count = await asyncio.gather(
                redis.sismember(known_key,      payload.device_id),
                redis.scard(multi_acct_key),
                redis.scard(cards_key),
            )

            # Dispositivo nuevo para este usuario
            if not is_known:
                score += 20.0

            # Múltiples cuentas distintas en el mismo dispositivo (24h)
            if user_count and user_count >= 3:
                score += 65.0   # Muy sospechoso: device compartido entre cuentas
            elif user_count and user_count == 2:
                score += 20.0

            # RF-KYC-002: 3+ tarjetas distintas en este dispositivo en 10 min
            if card_count and card_count >= 3:
                score += 70.0

        except Exception as e:
            logger.error(f"[KYCDevice] Redis error: {e}")

        return min(score, 100.0)

    # ------------------------------------------------------------------ #
    #  API Externa (Sift / Kount)                                        #
    # ------------------------------------------------------------------ #

    async def _query_external_api(self, payload: TransactionPayload) -> float:
        """
        Consulta a proveedor externo con timeout estricto de 80ms.
        Si falla o hace timeout → usa último score cacheado (TTL 30min).
        Si no hay caché → retorna score neutro (no penaliza por infra).
        Tiempo esperado: < 80ms con timeout.
        """
        cache_key = f"ext:score:{payload.user_id}:{payload.device_id}"
        redis     = redis_manager.client

        try:
            async with asyncio.timeout(0.080):
                # ── Reemplazar con llamada real a Sift o Kount ────────
                # response = await sift_client.score(
                #     user_id=str(payload.user_id),
                #     device_id=payload.device_id,
                #     ip=payload.ip_address,
                # )
                # ext_score = response.score * 100
                ext_score = 10.0  # Placeholder hasta integrar proveedor real

            # Cachear resultado exitoso por 30 minutos
            await redis.setex(cache_key, 1_800, str(ext_score))
            return ext_score

        except asyncio.TimeoutError:
            logger.warning(
                f"[ExternalAPI] Timeout para user={payload.user_id} — "
                f"usando caché o fallback"
            )
        except Exception as e:
            logger.error(f"[ExternalAPI] Error: {e}")

        # Intentar usar score cacheado antes del fallback
        try:
            cached = await redis.get(cache_key)
            if cached:
                return float(cached)
        except Exception:
            pass

        # Sin respuesta ni caché: score neutro — no penalizar al usuario
        # por un problema de infraestructura externo
        return 15.0

    # ------------------------------------------------------------------ #
    #  Velocidad                                                         #
    # ------------------------------------------------------------------ #

    async def _evaluate_velocity(self, payload: TransactionPayload) -> float:
        """
        Delega en TopUpRulesEngine (tu módulo original, sin cambios).
        Tiempo esperado: 5-10ms.
        """
        try:
            return await self.topup_engine.evaluate(
                payload, redis_manager.client
            )
        except Exception as e:
            logger.error(f"[Velocity] Error: {e}")
            return 20.0   # Score neutro como fallback

    # ------------------------------------------------------------------ #
    #  Motor de decisión                                                 #
    # ------------------------------------------------------------------ #

    def _determine_action(
        self,
        score: int,
        p2p_result,
    ) -> Tuple[ActionDecision, Optional[ChallengeType], str]:
        """
        Convierte el score numérico en una acción accionable.

        Si hay retención preventiva P2P (cuenta nueva receptora o drenado),
        usamos CHALLENGE_HARD en lugar de APPROVE aunque el score sea bajo,
        para aplicar la retención de fondos de 24h.
        """
        # Override de retención preventiva P2P
        if p2p_result and p2p_result.should_hold_funds and score <= 30:
            return (
                ActionDecision.ACTION_CHALLENGE_HARD,
                ChallengeType.THREEDS,
                "Tu transferencia está siendo verificada por seguridad.",
            )

        if score <= 30:
            return (
                ActionDecision.ACTION_APPROVE,
                None,
                "Transacción aprobada.",
            )
        elif score <= 60:
            return (
                ActionDecision.ACTION_CHALLENGE_SOFT,
                ChallengeType.SMS_OTP,
                "Por tu seguridad, necesitamos verificar tu identidad.",
            )
        elif score <= 75:
            return (
                ActionDecision.ACTION_CHALLENGE_HARD,
                ChallengeType.THREEDS,
                "Se requiere verificación adicional para continuar.",
            )
        elif score <= 90:
            return (
                ActionDecision.ACTION_BLOCK_REVIEW,
                None,
                "Tu transacción está siendo revisada. Te notificaremos pronto.",
            )
        else:
            return (
                ActionDecision.ACTION_BLOCK_PERM,
                None,
                "Operación declinada por políticas de seguridad.",
            )

    # ------------------------------------------------------------------ #
    #  Construcción y firma de respuesta                                 #
    # ------------------------------------------------------------------ #

    def _build_response(
        self,
        evaluation_id: uuid.UUID,
        action: ActionDecision,
        risk_score: int,
        challenge: Optional[ChallengeType],
        reason_codes: list,
        user_message: str,
        processing_ms: int,
    ) -> FraudEvaluationResponse:
        """
        Construye la respuesta y la firma con HMAC-SHA256.

        La firma cubre transaction_id + action + risk_score.
        El Wallet debe verificar esta firma antes de actuar sobre la decisión
        para prevenir manipulación de respuestas en tránsito.

        Verificación en el Wallet:
            expected = hmac.new(secret, payload_bytes, sha256).hexdigest()
            assert response.signature == expected
        """
        # Payload canónico para firma (sort_keys para determinismo)
        signable = json.dumps(
            {
                "transaction_id": str(evaluation_id),
                "action":         action.value,
                "risk_score":     risk_score,
            },
            sort_keys   = True,
            separators  = (",", ":"),
        ).encode()

        signature = hmac_lib.new(
            _HMAC_SECRET,
            signable,
            hashlib.sha256,
        ).hexdigest()

        return FraudEvaluationResponse(
            transaction_id = evaluation_id,
            action         = action,
            risk_score     = risk_score,
            challenge_type = challenge,
            reason_codes   = list(set(reason_codes)),   # deduplicar
            user_message   = user_message,
            response_time_ms = processing_ms,
            signature      = signature,
        )

    # ------------------------------------------------------------------ #
    #  Utilidades                                                        #
    # ------------------------------------------------------------------ #

    def _safe_float(
        self, result, module_name: str, fallback: float
    ) -> float:
        """
        Extrae un float de un resultado de gather.
        Si el módulo lanzó una excepción, logea el error y usa el fallback.
        El fallback es siempre un valor moderado — nunca 0 (subestimaría
        el riesgo) ni 100 (bloquearía usuarios legítimos).
        """
        if isinstance(result, Exception):
            logger.error(
                f"[Orchestrator] Módulo '{module_name}' falló: {result}"
            )
            return fallback
        if isinstance(result, (int, float)):
            return float(result)
        return fallback

    def _safe_result(self, result, module_name: str):
        """
        Extrae un resultado de objeto de gather.
        Retorna None si el módulo falló — el orquestador maneja None
        en cada lugar donde se usa el resultado.
        """
        if isinstance(result, Exception):
            logger.error(
                f"[Orchestrator] Módulo '{module_name}' falló: {result}"
            )
            return None
        return result

    # ------------------------------------------------------------------ #
    #  Background updates — fire-and-forget                              #
    # ------------------------------------------------------------------ #

    async def _background_updates(
        self,
        payload:     TransactionPayload,
        final_score: int,
        action:      ActionDecision,
        p2p_result,
        response:    Optional["FraudEvaluationResponse"] = None,
        db:          Optional[AsyncSession] = None,
    ) -> None:
        """
        Actualiza todos los contadores y perfiles en Redis después de
        que la respuesta ya fue enviada al Wallet.

        Se ejecuta como tarea independiente via asyncio.create_task().
        Si falla, solo se logea — no afecta la transacción ya evaluada.

        Actualiza:
          - Dispositivos conocidos del usuario (para reducir penalización
            de "dispositivo nuevo" en futuras evaluaciones)
          - Mapa device_id → user_id (para detectar multi-cuenta)
          - Tarjetas en ventana de 10 min (para RF-KYC-002)
          - Risk score acumulado del usuario (para análisis P2P)
          - Contadores de confianza (solo si la tx fue aprobada)
          - Historial de destinatarios P2P (para "destinatario frecuente")
        """
        redis   = redis_manager.client
        user_id = str(payload.user_id)
        approved = action == ActionDecision.ACTION_APPROVE

        try:
            pipe = redis.pipeline()

            # Registrar este dispositivo como conocido para el usuario
            pipe.sadd(f"device:user:{user_id}:known_devices", payload.device_id)
            pipe.expire(f"device:user:{user_id}:known_devices", 60 * 60 * 24 * 90)

            # Registrar este user_id en el mapa del dispositivo (multi-cuenta)
            pipe.sadd(f"device:{payload.device_id}:users_24h", user_id)
            pipe.expire(f"device:{payload.device_id}:users_24h", 86_400)

            # Registrar el BIN en la ventana de 10 minutos (RF-KYC-002)
            pipe.sadd(f"device:{payload.device_id}:cards_10min", payload.card_bin)
            pipe.expire(f"device:{payload.device_id}:cards_10min", 600)

            await pipe.execute()

            # Actualizar risk score acumulado del usuario
            # (se usa en P2P para propagar riesgo al emisor si este
            # usuario es receptor en una futura transacción)
            await self.p2p_analyzer.update_accumulated_risk(user_id, final_score)

            # Solo si la transacción fue aprobada actualizamos
            # los contadores positivos de confianza
            if approved:
                await self.trust_service.record_successful_transaction(
                    user_id      = user_id,
                    device_id    = payload.device_id,
                    country_code = getattr(payload, "ip_country", "MX"),
                )

                # Si fue P2P aprobada, actualizar historial de destinatarios
                if payload.transaction_type == "P2P_SEND" and payload.recipient_id:
                    await self.behavior_engine.record_successful_tx(
                        user_id      = user_id,
                        recipient_id = str(payload.recipient_id),
                        amount       = float(payload.amount),
                        currency     = payload.currency,
                    )

            # ── Persistir auditoría en PostgreSQL ────────────────────
            if db is not None and response is not None:
                await AuditRepository(db).save_evaluation(
                    payload     = payload,
                    final_score = final_score,
                    action      = action,
                    response    = response,
                )

        except Exception as e:
            logger.error(
                f"[Background] Error actualizando contadores user={user_id}: {e}"
            )


# ── Singleton ─────────────────────────────────────────────────────────
# Misma interfaz que el archivo original.
# El router llama: await fraud_orchestrator.evaluate_transaction(payload)
# No es necesario cambiar nada en app/api/routers/transactions.py
fraud_orchestrator = FraudOrchestrator()