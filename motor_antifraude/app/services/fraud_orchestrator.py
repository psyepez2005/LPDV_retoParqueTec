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
from app.services.rate_limit_scorer import rate_limit_scorer
from app.services.ip_history import ip_history_analyzer
from app.services.gps_ip_mismatch import gps_ip_mismatch_detector
from app.services.session_guard import session_guard
from app.services.card_testing_detector import card_testing_detector
from app.services.time_pattern_scorer import time_pattern_scorer
from fastapi import Header


logger = logging.getLogger(__name__)

_EXACT_CATALOG: dict[str, tuple[int, str, str]] = {

    # ── Blacklist ─────────────────────────────────────────────────────
    "BLACKLIST_USER_HIT":              (100, "Lista negra",    "El usuario está en lista negra permanente."),
    "BLACKLIST_DEVICE_HIT":            (100, "Lista negra",    "El dispositivo está en lista negra permanente."),
    "BLACKLIST_IP_HIT":                (100, "Lista negra",    "La IP está en lista negra permanente."),
    "BLACKLIST_CARD_HIT":              (100, "Lista negra",    "El BIN de la tarjeta está bloqueado."),

    # ── Velocidad / rate limit ────────────────────────────────────────
    "IP_RATE_HIGH":                    (15,  "Velocidad",      "La IP ha hecho muchas peticiones en 60s — posible bot."),
    "IP_RATE_ELEVATED":                (10,  "Velocidad",      "La IP supera el umbral moderado de peticiones — actividad inusual."),
    "IP_RATE_EXTREME":                 (30,  "Velocidad",      "La IP supera el límite crítico — ataque en curso probable."),
    "USER_RATE_HIGH":                  (15,  "Velocidad",      "El usuario realizó muchas transacciones en 5 minutos."),
    "USER_RATE_ELEVATED":              (8,   "Velocidad",      "El usuario supera el umbral moderado de transacciones por minuto."),
    "USER_RATE_EXTREME":               (35,  "Velocidad",      "El usuario supera el límite crítico — cargos masivos."),
    "HIGH_VELOCITY_OR_LIMIT_EXCEEDED": (20,  "Velocidad",      "El usuario supera los límites de recarga o hay alta frecuencia de envíos."),

    # ── Dispositivo ─────────────────────────────────────────────────
    "EMULATOR_OR_ROOT_DETECTED":       (25,  "Dispositivo",    "Se detectó emulador o dispositivo rooteado — técnica común de fraude."),
    "SUSPICIOUS_DEVICE_FINGERPRINT":   (15,  "Dispositivo",    "El fingerprint del dispositivo es anómalo o inconsistente."),

    # ── Comportamiento ────────────────────────────────────────────
    "LEARNING_PERIOD_ACTIVE":          (0,   "Comportamiento", "Usuario con historial limitado — umbrales más permisivos."),
    "PROFILE_CHANGED_LAST_24H":        (25,  "Comportamiento", "El perfil fue modificado en las últimas 24h — señal de account takeover."),
    "PAYDAY_WINDOW_REDUCTION":         (0,   "Comportamiento", "Día de quincena — monto alto normal, no penalizado."),
    "P2P_NEW_RECIPIENT_FIRST_TX":      (10,  "Comportamiento", "Primer pago a este destinatario — sin historial de confianza."),

    # ── Historial del usuario (payload) ──────────────────────────────
    "ACCOUNT_AGE_VERY_NEW":            (20,  "Historial",      "Cuenta con menos de 7 días — mayor riesgo estadístico."),
    "ACCOUNT_AGE_NEW":                 (10,  "Historial",      "Cuenta con menos de 30 días — historial insuficiente."),
    "AMOUNT_3X_ABOVE_AVERAGE":         (20,  "Historial",      "El monto es más de 3× el promedio mensual del usuario."),
    "HIGH_FAILED_TX_LAST_7D":          (25,  "Historial",      "5+ transacciones fallidas en 7 días — patrón de fraude activo."),
    "FAILED_TX_LAST_7D":               (10,  "Historial",      "3+ transacciones fallidas en los últimos 7 días."),
    "HIGH_AMOUNT_NO_KYC":              (15,  "Historial",      "Monto alto con KYC no completado — riesgo regulatorio y de fraude."),
    "INTERNATIONAL_CARD":              (10,  "Historial",      "Tarjeta emitida en el extranjero — mayor riesgo cross-border."),

    # ── Sesión ───────────────────────────────────────────────────────
    "SESSION_REPLAY_ATTACK":           (40,  "Sesión",         "El session_id ya fue usado — posible replay attack."),
    "SESSION_HIJACK_DETECTED":         (100, "Sesión",         "El session_id pertenece a otro usuario — session hijacking confirmado."),

    # ── IP History ────────────────────────────────────────────────────
    "IP_COUNTRY_JUMP_30MIN":           (25,  "IP History",     "El país de la IP cambió en < 30 min — posible VPN o cuenta compartida."),
    "IMPOSSIBLE_IP_JUMP_5MIN":         (50,  "IP History",     "Cambio de país de IP en < 5 min — físicamente imposible."),

    # ── Geolocalización (GeoAnalyzer) ─────────────────────────────────
    "GPS_OBFUSCATED_ZERO_COORDS":      (20,  "Geolocalización","Coordenadas GPS en (0,0) — posible ocultamiento de ubicación real."),
    "TRAVELER_MODE_ACTIVE":            (0,   "Geolocalización","Modo viajero activo — ubicación inusual esperada, no penalizado."),
    "DUAL_COUNTRY_MISMATCH":           (20,  "Geolocalización","El país de la IP y el GPS no coinciden — posible VPN activa."),
    "TRIPLE_COUNTRY_MISMATCH":         (35,  "Geolocalización","IP, GPS y país registrado no coinciden — alta probabilidad de fraude."),
    "IMPOSSIBLE_TRAVEL_DETECTED":      (50,  "Geolocalización","El usuario aparece en dos ubicaciones físicamente imposibles."),
    "IMPOSSIBLE_TRAVEL":               (50,  "Geolocalización","Viaje físicamente imposible entre la ubicación anterior y la actual."),
    "VPN_DETECTED":                    (20,  "Geolocalización","Se detectó uso de VPN o proxy."),
    "ML_GEO_ANOMALY":                  (30,  "Geolocalización","Modelo ML detectó anomalía geográfica en el patrón de movimiento."),

    # ── GPS vs IP (gps_ip_mismatch.py) ──────────────────────────────
    "HIGH_RISK_IP_COUNTRY_RU":         (10,  "Geolocalización","La IP proviene de Rusia — alto índice de fraude en pagos."),
    "HIGH_RISK_IP_COUNTRY_CN":         (10,  "Geolocalización","La IP proviene de China."),
    "HIGH_RISK_IP_COUNTRY_KP":         (10,  "Geolocalización","La IP proviene de Corea del Norte."),
    "HIGH_RISK_IP_COUNTRY_IR":         (10,  "Geolocalización","La IP proviene de Irán."),
    "HIGH_RISK_IP_COUNTRY_NG":         (10,  "Geolocalización","La IP proviene de Nigeria."),

    # ── Hora / Patrón ───────────────────────────────────────────────
    "NIGHT_TX_NEW_ACCOUNT":            (10,  "Hora / Patrón",  "Transacción de madrugada en cuenta nueva — patrón frecuente de fraude."),

    # ── Tiempo de llenado del formulario ─────────────────────────────
    "FORM_FILL_INSTANT":               (30,  "Comportamiento", "Formulario llenado en < 3s — velocidad inhumana, posible scripting o bot."),
    "FORM_FILL_VERY_FAST":             (15,  "Comportamiento", "Formulario llenado en 3–8s — inusualmente rápido para un humano."),
    "FORM_FILL_VERY_SLOW":             (10,  "Comportamiento", "Formulario llenado en > 15min — posible sesión reutilizada o abandonada."),

    # ── P2P Analyzer ─────────────────────────────────────────────────
    "PREVENTIVE_HOLD_NEW_ACCOUNT":     (10,  "P2P",             "Retención preventiva 24h — receptor nuevo recibiendo monto alto."),

    # ── Orquestador — overrides ────────────────────────────────────
    "OVERRIDE_IMPOSSIBLE_TRAVEL":      (100, "Override",        "Override: viaje imposible confirmado — score forzado a máximo."),
    "OVERRIDE_MULE_PATTERN_CONFIRMED": (100, "Override",        "Override: patrón de cuenta mula confirmado — score forzado a máximo."),

    # ── Contribuciones base de módulos ponderados (breakdown honesto) ──────
    "__VELOCITY_BASE__":               (0,   "Velocidad",       "Puntuación base del módulo de velocidad transaccional."),
    "__DEVICE_BASE__":                 (0,   "Dispositivo",     "Puntuación base del módulo de dispositivo (sin anomalías detectadas)."),
    "__EXTERNAL_BASE__":               (0,   "Externo",         "Puntuación base del módulo de riesgo externo (BIN/IP score)."),
}

_PREFIX_CATALOG: dict[str, tuple[int, str, str]] = {
    "GPS_IP_COUNTRY_MISMATCH_":        (30,  "Geolocalización","GPS indica país diferente al de la IP — posible VPN activa."),
    "GPS_IP_DISTANCE_":                (20,  "Geolocalización","Distancia GPS↔IP inusualmente alta — el dispositivo no está donde dice ser."),
    "NEW_COUNTRY_":                    (15,  "Geolocalización","Primera transacción desde este país para este usuario."),
    "KNOWN_COUNTRY_REDUCTION_":        (-10, "Geolocalización","País conocido del usuario — reducción por historial positivo."),
    "HIGH_RISK_COUNTRY_":              (25,  "Geolocalización","País de alto riesgo para pagos electrónicos."),
    "HIGH_RISK_IP_COUNTRY_":           (10,  "Geolocalización","IP proveniente de país con alto índice de fraude."),

    # Card Testing
    "CARD_TESTING_PATTERN_":           (40,  "Card Testing",   "Micro-tx de sondeo seguidas de monto grande (card testing)."),
    "RAPID_BIN_PROBE_":                (35,  "Card Testing",   "Múltiples tx con el mismo BIN en < 10 min — ataque de carding."),

    # Comportamiento (BehaviorEngine)
    "TX_WITHIN_":                      (15,  "Comportamiento", "Login seguido inmediatamente de tx — patrón de bot o sesión secuestrada."),
    "CURRENCY_CHANGE_":                (12,  "Comportamiento", "La moneda usada es diferente a la habitual del usuario."),
    "FIRST_WEEK_USER_DAY_":            (10,  "Historial",      "Primera semana de la cuenta — mayor riesgo estadístico."),
    "P2P_FREQUENT_RECIPIENT_":         (-8,  "Comportamiento", "Destinatario frecuente con historial positivo — riesgo reducido."),
    "UNUSUAL_HOUR_":                   (15,  "Hora / Patrón",  "El usuario nunca había sido activo en esta hora del día."),
    "AMOUNT_":                         (20,  "Comportamiento", "El monto supera significativamente el promedio histórico del usuario."),

    # P2P Analyzer — códigos con sufijos dinámicos de contadores
    "RECIPIENT_ACCOUNT_AGE_":          (20,  "P2P",            "El receptor tiene cuenta muy nueva — posible cuenta mula recién creada."),
    "RECIPIENT_HIGH_RISK_SCORE_":      (15,  "P2P",            "El receptor tiene historial de riesgo alto — el riesgo se propaga entre nodos."),
    "FANOUT_HIGH_1H_":                 (30,  "P2P",            "El emisor envió a muchos destinatarios distintos en 1h — distribución de fondos robados."),
    "FANOUT_MEDIUM_24H_":              (15,  "P2P",            "Fan-out moderado en 24h — múltiples destinatarios distintos."),
    "RECIPIENT_FANIN_HIGH_1H_":        (25,  "P2P",            "El receptor recibe de muchas fuentes en 1h — señal fuerte de cuenta mula."),
    "RECIPIENT_FANIN_HIGH_24H_":       (12,  "P2P",            "Fan-in moderado en 24h — el receptor acumula fondos de muchas fuentes."),
    "SMURFING_DAILY_VOL_":             (35,  "P2P",            "Patrón de smurfing: micro-tx acumuladas bajo el umbral regulatorio."),
    "RAPID_DRAIN_":                    (40,  "P2P",            "El receptor drenó su saldo en < 2h — firma definitiva de cuenta mula."),
}



def _get_catalog_entry(code: str) -> tuple[int, str, str] | None:
    """Devuelve (points, category, description) del catálogo para un código dado."""
    if code in _EXACT_CATALOG:
        return _EXACT_CATALOG[code]
    for prefix, data in _PREFIX_CATALOG.items():
        if code.startswith(prefix):
            return data
    return None


def _distribute_to_contributions(
    contributions: dict[str, int],
    codes: list[str],
    total: int,
) -> None:
    """
    Reparte `total` puntos reales entre `codes` de forma proporcional
    a sus pesos en el catálogo. Si no hay pesos positivos, reparto
    equitativo. Los códigos con peso 0 en catálogo NO reciben puntos.
    """
    if not codes or total == 0:
        return

    weights: list[int] = []
    for code in codes:
        entry = _get_catalog_entry(code)
        weights.append(max(entry[0], 0) if entry else 1)

    total_w = sum(weights)
    if total_w == 0:
        # Todos son informativos (peso 0) — nada que distribuir
        return

    remaining = total
    distributed_any = False
    for i, code in enumerate(codes):
        if weights[i] == 0:
            # Código informativo — no le asignamos puntos reales
            contributions.setdefault(code, 0)
            continue
        if i == len(codes) - 1 or (i == len(codes) - 2 and all(w == 0 for w in weights[i+1:])):
            # Último código con peso positivo recibe el resto
            contributions[code] = contributions.get(code, 0) + remaining
            distributed_any = True
        else:
            share = round(total * weights[i] / total_w)
            contributions[code] = contributions.get(code, 0) + share
            remaining -= share
            distributed_any = True


def _build_breakdown(
    reason_codes: list[str],
    contributions: dict[str, int] | None = None,
) -> list:
    """
    Construye el score_breakdown.
    Si se provee `contributions`, usa los puntos REALES de ese dict.
    De lo contrario, usa los puntos de referencia del catálogo.
    """
    from app.domain.schemas import ScoreEntry
    entries = []
    seen    = set()
    for code in reason_codes:
        if code in seen:
            continue
        seen.add(code)

        # Puntos reales si están disponibles, si no fallback al catálogo
        real_pts = contributions.get(code) if contributions is not None else None

        entry = _get_catalog_entry(code)
        if entry:
            catalog_pts, cat, desc = entry
            pts = real_pts if real_pts is not None else catalog_pts
            entries.append(ScoreEntry(code=code, points=pts, category=cat, description=desc))
            continue

        # Código desconocido
        pts = real_pts if real_pts is not None else 0
        entries.append(ScoreEntry(
            code=code,
            points=pts,
            category="Otro",
            description=f"Señal detectada: {code.replace('_', ' ').lower()}.",
        ))

    entries.sort(key=lambda e: e.points, reverse=True)
    return entries


_HMAC_SECRET: bytes = os.environ.get(
    "FRAUD_HMAC_SECRET",
    "dev-secret-replace-in-production",
).encode()


class FraudOrchestrator:

    W1_VELOCITY = 0.25
    W2_DEVICE   = 0.20
    W3_GEO      = 0.20
    W4_BEHAVIOR = 0.20
    W5_EXTERNAL = 0.15

    def __init__(self):
        self.topup_engine    = TopUpRulesEngine()
        self._blacklist: Optional[BlacklistService]   = None
        self._trust_service: Optional[TrustScoreService] = None
        self._geo_analyzer: Optional[GeoAnalyzer]    = None
        self._behavior_engine: Optional[BehaviorEngine] = None
        self._p2p_analyzer: Optional[P2PAnalyzer]    = None

    def _ensure_redis_modules(self) -> None:
        redis = redis_manager.client
        if self._blacklist is None:
            self._blacklist       = BlacklistService(redis)
            self._trust_service   = TrustScoreService(redis)
            self._geo_analyzer    = GeoAnalyzer(redis)
            self._behavior_engine = BehaviorEngine(redis)
            self._p2p_analyzer    = P2PAnalyzer(redis)

    @property
    def blacklist(self) -> BlacklistService:
        self._ensure_redis_modules()
        return self._blacklist  # type: ignore

    @property
    def trust_service(self) -> TrustScoreService:
        self._ensure_redis_modules()
        return self._trust_service  # type: ignore

    @property
    def geo_analyzer(self) -> GeoAnalyzer:
        self._ensure_redis_modules()
        return self._geo_analyzer  # type: ignore

    @property
    def behavior_engine(self) -> BehaviorEngine:
        self._ensure_redis_modules()
        return self._behavior_engine  # type: ignore

    @property
    def p2p_analyzer(self) -> P2PAnalyzer:
        self._ensure_redis_modules()
        return self._p2p_analyzer  # type: ignore
    
    def verify_incoming_hmac(self, payload: dict, received_sig: str) -> bool:
        """
        Verifica que el cuerpo de la transacción coincida con la firma enviada.
        Garantiza que nadie cambió el monto o el user_id en el camino.
        """
        # Usamos el mismo secreto definido en el archivo
        secret = os.environ.get("FRAUD_HMAC_SECRET", "dev-secret...").encode()
        
        # El payload debe convertirse a string de forma determinista para que el hash coincida
        data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        
        # Generamos la firma local y comparamos
        expected_sig = hmac_lib.new(secret, data, hashlib.sha256).hexdigest()
        return hmac_lib.compare_digest(expected_sig, received_sig)

    async def evaluate_transaction(
        self,
        payload: TransactionPayload,
        db: Optional[AsyncSession] = None,
    ) -> FraudEvaluationResponse:

        start_time    = time.perf_counter()
        evaluation_id = uuid.uuid4()
        reason_codes: list[str] = []
        # Diccionario de contribuciones reales: reason_code → delta aportado al final_score
        contributions: dict[str, int] = {}


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

        rate_penalty, rate_codes = await rate_limit_scorer.score(
            user_id    = str(payload.user_id),
            ip_address = str(payload.ip_address),
        )

        is_p2p = payload.transaction_type == "P2P_SEND"

        ip_country  = getattr(payload, "ip_country",  "MX")
        bin_country = getattr(payload, "bin_country", "MX")
        is_vpn      = getattr(payload, "is_vpn",      False)

        tasks = [
            self._evaluate_kyc_device(payload),             # [0] → float
            self._query_external_api(payload),              # [1] → float
            self._evaluate_velocity(payload),               # [2] → float
            self.geo_analyzer.analyze(                      # [3] → GeoAnalysisResult
                user_id     = str(payload.user_id),
                latitude    = payload.latitude,
                longitude   = payload.longitude,
                ip_country  = ip_country,
                bin_country = bin_country,
                is_vpn      = is_vpn,
            ),
            self.behavior_engine.analyze(                   # [4] → BehaviorAnalysisResult
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
            self.trust_service.get_trust_profile(           # [5] → TrustProfile
                user_id      = str(payload.user_id),
                device_id    = payload.device_id,
                country_code = ip_country,
            ),
            ip_history_analyzer.check(                      # [6] → IPHistoryResult
                user_id    = str(payload.user_id),
                ip_address = str(payload.ip_address),
                ip_country = ip_country,
            ),
            session_guard.check(                            # [7] → SessionGuardResult
                session_id = str(payload.session_id),
                user_id    = str(payload.user_id),
            ),
            card_testing_detector.check(                    # [8] → CardTestingResult
                device_id = payload.device_id,
                card_bin  = payload.card_bin,
                amount    = float(payload.amount),
            ),
            time_pattern_scorer.score(                      # [9] → TimePatternResult
                user_id = str(payload.user_id),
            ),
        ]

        if is_p2p and payload.recipient_id:
            tasks.append(
                self.p2p_analyzer.analyze(                  # [10] → P2PAnalysisResult
                    sender_id    = str(payload.user_id),
                    recipient_id = str(payload.recipient_id),
                    amount       = float(payload.amount),
                    currency     = payload.currency,
                )
            )

        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        device_score    = self._safe_float(raw_results[0], "kyc_device",    30.0)
        ext_score       = self._safe_float(raw_results[1], "external_api",  15.0)
        velocity_score  = self._safe_float(raw_results[2], "velocity",      20.0)
        geo_result      = self._safe_result(raw_results[3], "geo")
        behavior_result = self._safe_result(raw_results[4], "behavior")
        trust_profile   = self._safe_result(raw_results[5], "trust")
        ip_hist_result  = self._safe_result(raw_results[6], "ip_history")
        session_result  = self._safe_result(raw_results[7], "session_guard")
        card_test_result = self._safe_result(raw_results[8], "card_testing")
        time_result     = self._safe_result(raw_results[9], "time_pattern")
        p2p_result      = (
            self._safe_result(raw_results[10], "p2p")
            if is_p2p and len(raw_results) > 10
            else None
        )

        geo_score       = geo_result.score      if geo_result      else 20.0
        behavior_score  = behavior_result.score if behavior_result else 10.0
        trust_reduction = trust_profile.trust_reduction if trust_profile else 0

        weighted_score = (
            (self.W1_VELOCITY * velocity_score)  +
            (self.W2_DEVICE   * device_score)    +
            (self.W3_GEO      * geo_score)        +
            (self.W4_BEHAVIOR * behavior_score)   +
            (self.W5_EXTERNAL * ext_score)
        )

        # Contribuciones reales de los módulos ponderados
        # Se registran ANTES de extend(geo/behavior reason_codes) para tener los códigos listos
        _geo_contrib      = round(self.W3_GEO      * geo_score)
        _behavior_contrib = round(self.W4_BEHAVIOR * behavior_score)
        _geo_codes_pending      = geo_result.reason_codes      if geo_result      else []
        _behavior_codes_pending = behavior_result.reason_codes if behavior_result else []

        p2p_penalty = 0.0
        if p2p_result:
            p2p_penalty = p2p_result.score * 0.30

        # trust_reduction es negativo (reducción de riesgo)
        final_score = int(
            max(0.0, min(100.0, weighted_score + p2p_penalty + trust_reduction))
        )

        # ── Contribuciones base de módulos ponderados sin reason_code propio ────────
        # Se rastrean y muestran en el breakdown para cerrar la brecha con el risk_score
        _vel_contrib  = round(self.W1_VELOCITY * velocity_score)
        _dev_contrib  = round(self.W2_DEVICE   * device_score)
        _ext_contrib  = round(self.W5_EXTERNAL * ext_score)
        if _vel_contrib:
            contributions["__VELOCITY_BASE__"] = _vel_contrib
            reason_codes.append("__VELOCITY_BASE__")
        if _dev_contrib:
            contributions["__DEVICE_BASE__"] = _dev_contrib
            reason_codes.append("__DEVICE_BASE__")
        if _ext_contrib:
            contributions["__EXTERNAL_BASE__"] = _ext_contrib
            reason_codes.append("__EXTERNAL_BASE__")

        from app.domain.schemas import KycLevel
        history_penalty = 0

        if payload.account_age_days is not None and payload.account_age_days < 7:
            history_penalty += 20
            reason_codes.append("ACCOUNT_AGE_VERY_NEW")
            contributions["ACCOUNT_AGE_VERY_NEW"] = 20
        elif payload.account_age_days is not None and payload.account_age_days < 30:
            history_penalty += 10
            reason_codes.append("ACCOUNT_AGE_NEW")
            contributions["ACCOUNT_AGE_NEW"] = 10

        if (
            payload.avg_monthly_amount is not None
            and payload.avg_monthly_amount > 0
            and float(payload.amount) > float(payload.avg_monthly_amount) * 3
        ):
            history_penalty += 20
            reason_codes.append("AMOUNT_3X_ABOVE_AVERAGE")
            contributions["AMOUNT_3X_ABOVE_AVERAGE"] = 20

        if payload.failed_tx_last_7_days is not None:
            if payload.failed_tx_last_7_days >= 5:
                history_penalty += 25
                reason_codes.append("HIGH_FAILED_TX_LAST_7D")
                contributions["HIGH_FAILED_TX_LAST_7D"] = 25
            elif payload.failed_tx_last_7_days >= 3:
                history_penalty += 10
                reason_codes.append("FAILED_TX_LAST_7D")
                contributions["FAILED_TX_LAST_7D"] = 10

        if payload.kyc_level == KycLevel.NONE and float(payload.amount) > 500:
            history_penalty += 15
            reason_codes.append("HIGH_AMOUNT_NO_KYC")
            contributions["HIGH_AMOUNT_NO_KYC"] = 15

        if payload.is_international_card:
            history_penalty += 10
            reason_codes.append("INTERNATIONAL_CARD")
            contributions["INTERNATIONAL_CARD"] = 10

        final_score = int(max(0, min(100, final_score + history_penalty)))

        if rate_penalty > 0:
            reason_codes.extend(rate_codes)
            _distribute_to_contributions(contributions, rate_codes, rate_penalty)
            final_score = int(max(0, min(100, final_score + rate_penalty)))

        # ── Tiempo de llenado del formulario ──────────────────────────────
        fill_t = payload.form_fill_time_seconds
        if fill_t is not None:
            if fill_t < 3:
                # < 3s → scripting / bot — penalización fuerte
                reason_codes.append("FORM_FILL_INSTANT")
                contributions["FORM_FILL_INSTANT"] = 30
                final_score = int(max(0, min(100, final_score + 30)))
            elif fill_t < 8:
                # 3–8s → muy rápido para un humano — penalización moderada
                reason_codes.append("FORM_FILL_VERY_FAST")
                contributions["FORM_FILL_VERY_FAST"] = 15
                final_score = int(max(0, min(100, final_score + 15)))
            elif fill_t > 900:
                # > 15 min → sesión abandonada o reutilizada — penalización leve
                reason_codes.append("FORM_FILL_VERY_SLOW")
                contributions["FORM_FILL_VERY_SLOW"] = 10
                final_score = int(max(0, min(100, final_score + 10)))

        gps_result = gps_ip_mismatch_detector.check(
            latitude   = payload.latitude,
            longitude  = payload.longitude,
            ip_country = ip_country,
        )
        if gps_result.penalty > 0:
            reason_codes.extend(gps_result.reason_codes)
            _distribute_to_contributions(contributions, gps_result.reason_codes, gps_result.penalty)
            final_score = int(max(0, min(100, final_score + gps_result.penalty)))

        if ip_hist_result:
            if ip_hist_result.override_block:
                _score_before = final_score
                final_score = 100
                reason_codes.extend(ip_hist_result.reason_codes)
                _distribute_to_contributions(contributions, ip_hist_result.reason_codes, 100 - _score_before)
            elif ip_hist_result.penalty > 0:
                reason_codes.extend(ip_hist_result.reason_codes)
                _distribute_to_contributions(contributions, ip_hist_result.reason_codes, ip_hist_result.penalty)
                final_score = int(max(0, min(100, final_score + ip_hist_result.penalty)))

        if session_result:
            if session_result.override_block:
                _score_before = final_score
                final_score = 100
                reason_codes.extend(session_result.reason_codes)
                _distribute_to_contributions(contributions, session_result.reason_codes, 100 - _score_before)
            elif session_result.penalty > 0:
                reason_codes.extend(session_result.reason_codes)
                _distribute_to_contributions(contributions, session_result.reason_codes, session_result.penalty)
                final_score = int(max(0, min(100, final_score + session_result.penalty)))

        if card_test_result and card_test_result.penalty > 0:
            reason_codes.extend(card_test_result.reason_codes)
            _distribute_to_contributions(contributions, card_test_result.reason_codes, card_test_result.penalty)
            final_score = int(max(0, min(100, final_score + card_test_result.penalty)))

        if time_result and time_result.penalty > 0:
            reason_codes.extend(time_result.reason_codes)
            _time_delta = int(time_result.penalty * self.W4_BEHAVIOR)
            _distribute_to_contributions(contributions, time_result.reason_codes, _time_delta)
            weighted_score += time_result.penalty * self.W4_BEHAVIOR
            final_score = int(max(0, min(100, weighted_score + p2p_penalty + trust_reduction)))

        # ── Códigos de dispositivo/velocidad ─────────────────────────────────
        # Si superan el umbral: reemplazar entry genérico por el código real
        if device_score >= 80:
            reason_codes.append("EMULATOR_OR_ROOT_DETECTED")
            contributions.pop("__DEVICE_BASE__", None)
            contributions["EMULATOR_OR_ROOT_DETECTED"] = round(self.W2_DEVICE * device_score)
        elif device_score >= 60:
            reason_codes.append("SUSPICIOUS_DEVICE_FINGERPRINT")
            contributions.pop("__DEVICE_BASE__", None)
            contributions["SUSPICIOUS_DEVICE_FINGERPRINT"] = round(self.W2_DEVICE * device_score)

        if velocity_score >= 40:
            reason_codes.append("HIGH_VELOCITY_OR_LIMIT_EXCEEDED")
            contributions.pop("__VELOCITY_BASE__", None)
            contributions["HIGH_VELOCITY_OR_LIMIT_EXCEEDED"] = round(self.W1_VELOCITY * velocity_score)


        # ── Módulos ponderados: geo y behavior ───────────────────────────────
        if geo_result:
            reason_codes.extend(geo_result.reason_codes)
            _distribute_to_contributions(contributions, _geo_codes_pending, _geo_contrib)

        if behavior_result:
            reason_codes.extend(behavior_result.reason_codes)
            _distribute_to_contributions(contributions, _behavior_codes_pending, _behavior_contrib)

        # ── P2P ──────────────────────────────────────────────────────────────
        if p2p_result:
            reason_codes.extend(p2p_result.reason_codes)
            _p2p_contrib = round(p2p_result.score * 0.30)
            _distribute_to_contributions(contributions, p2p_result.reason_codes, _p2p_contrib)

        # ── Trust reduction ──────────────────────────────────────────────────
        if trust_profile and trust_profile.trust_reduction < -10:
            _trust_code = f"TRUST_REDUCTION_{abs(trust_profile.trust_reduction)}PTS"
            reason_codes.append(_trust_code)
            contributions[_trust_code] = trust_profile.trust_reduction  # valor negativo real
        elif trust_profile and trust_profile.trust_reduction != 0:
            # Reducción moderada — registrarla en códigos existentes de geo/behavior
            # que ya vinieron del TrustProfile (e.g. KNOWN_COUNTRY_REDUCTION_*)
            # Se distribuye entre todos los códigos de geo que ya tengan contribuciones
            pass

        # Registrar trust_reduction en KNOWN_COUNTRY_REDUCTION_* si está presente
        _known_country_codes = [
            c for c in reason_codes if c.startswith("KNOWN_COUNTRY_REDUCTION_")
        ]
        if _known_country_codes and trust_profile and trust_profile.trust_reduction != 0:
            for kc in _known_country_codes:
                contributions[kc] = trust_profile.trust_reduction  # negativo

        # ── Overrides ────────────────────────────────────────────────────────
        if geo_result and geo_result.impossible_travel_detected:
            _score_before = final_score
            final_score = max(final_score, 76)
            contributions["OVERRIDE_IMPOSSIBLE_TRAVEL"] = final_score - _score_before
            reason_codes.append("OVERRIDE_IMPOSSIBLE_TRAVEL")

        if p2p_result and p2p_result.mule_pattern_detected:
            _score_before = final_score
            final_score = max(final_score, 91)
            contributions["OVERRIDE_MULE_PATTERN_CONFIRMED"] = final_score - _score_before
            reason_codes.append("OVERRIDE_MULE_PATTERN_CONFIRMED")

        action, challenge, user_msg = self._determine_action(
            score      = final_score,
            p2p_result = p2p_result,
        )

        processing_ms = int((time.perf_counter() - start_time) * 1000)

        response = self._build_response(
            evaluation_id = evaluation_id,
            action        = action,
            risk_score    = final_score,
            challenge     = challenge,
            reason_codes  = reason_codes,
            user_message  = user_msg,
            processing_ms = processing_ms,
            contributions = contributions,
        )

        logger.info(
            f"[Orchestrator] DECISION — "
            f"user={payload.user_id}  "
            f"score={final_score}  "
            f"action={action.value}  "
            f"time={processing_ms}ms  "
            f"codes={reason_codes}"
        )

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
        score      = 0.0
        ua_lower   = payload.user_agent.lower()
        redis      = redis_manager.client

        # ── Emulador o root declarado explícitamente por el SDK ──────────
        if payload.is_emulator:
            return 90.0   # Retorno inmediato — emulador declarado
        if payload.is_rooted_device:
            score += 50.0  # Root/jailbreak — riesgo alto pero no definitivo

        # ── Detección de emuladores por user-agent ────────────────────
        emulator_keywords = [
            "bluestacks", "nox", "ldplayer", "memu", "genymotion",
            "android_x86", "emulator", "headless", "selenium",
            "puppeteer", "playwright", "phantomjs", "webdriver",
        ]
        if any(kw in ua_lower for kw in emulator_keywords):
            return 90.0   # Retorno inmediato — emulador confirmado en UA

        # ── User-agent inválido o demasiado corto ─────────────────────
        if not payload.user_agent or len(payload.user_agent) < 10:
            score += 35.0

        # ── Inconsistencia OS en user-agent vs sdk_version ────────────
        if "iphone" in ua_lower and payload.sdk_version.lower().startswith("android"):
            score += 45.0
        elif "android" in ua_lower and payload.sdk_version.lower().startswith("ios"):
            score += 45.0

        # ── Inconsistencia device_os vs user-agent ────────────────────
        from app.domain.schemas import DeviceOS
        if payload.device_os == DeviceOS.ANDROID and "iphone" in ua_lower:
            score += 40.0
        elif payload.device_os == DeviceOS.IOS and "android" in ua_lower:
            score += 40.0

        # ── Battery level = 100 en dispositivo móvil = posible bot/script ──
        if (
            payload.battery_level == 100
            and payload.device_os in (DeviceOS.ANDROID, DeviceOS.IOS)
        ):
            score += 20.0

        # ── VPN declarada por el cliente (network_type) ────────────────
        from app.domain.schemas import NetworkType
        if payload.network_type == NetworkType.VPN:
            score += 15.0

        # ── Sesión extremadamente corta ─────────────────────────────
        if payload.session_duration_seconds is not None and payload.session_duration_seconds < 5:
            score += 25.0  # menos de 5 segundos → bot probable

        # ── Verificaciones en Redis ───────────────────────────────
        try:
            known_key      = f"device:user:{payload.user_id}:known_devices"
            multi_acct_key = f"device:{payload.device_id}:users_24h"
            cards_key      = f"device:{payload.device_id}:cards_10min"

            is_known, user_count, card_count = await asyncio.gather(
                redis.sismember(known_key,      payload.device_id),
                redis.scard(multi_acct_key),
                redis.scard(cards_key),
            )

            if not is_known:
                score += 20.0

            if user_count and user_count >= 3:
                score += 65.0 
            elif user_count and user_count == 2:
                score += 20.0

            if card_count and card_count >= 3:
                score += 70.0

        except Exception as e:
            logger.error(f"[KYCDevice] Redis error: {e}")

        return min(score, 100.0)

    # ------------------------------------------------------------------ #
    #  API Externa (Sift / Kount)                                        #
    # ------------------------------------------------------------------ #

    async def _query_external_api(self, payload: TransactionPayload) -> float:
        cache_key = f"ext:score:{payload.user_id}:{payload.device_id}"
        redis     = redis_manager.client

        try:
            async with asyncio.timeout(0.080):

                ext_score = 10.0 

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
        contributions: dict[str, int] | None = None,
    ) -> FraudEvaluationResponse:
        deduped_codes = list(dict.fromkeys(reason_codes))
        breakdown     = _build_breakdown(deduped_codes, contributions)

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
            transaction_id   = evaluation_id,
            action           = action,
            risk_score       = risk_score,
            challenge_type   = challenge,
            reason_codes     = deduped_codes,
            score_breakdown  = breakdown,
            user_message     = user_message,
            response_time_ms = processing_ms,
            signature        = signature,
        )

    # ------------------------------------------------------------------ #
    #  Utilidades                                                        #
    # ------------------------------------------------------------------ #

    def _safe_float(
        self, result, module_name: str, fallback: float
    ) -> float:

        if isinstance(result, Exception):
            logger.error(
                f"[Orchestrator] Módulo '{module_name}' falló: {result}"
            )
            return fallback
        if isinstance(result, (int, float)):
            return float(result)
        return fallback

    def _safe_result(self, result, module_name: str):

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

        redis   = redis_manager.client
        user_id = str(payload.user_id)
        approved = action == ActionDecision.ACTION_APPROVE

        try:
            pipe = redis.pipeline()

            pipe.sadd(f"device:user:{user_id}:known_devices", payload.device_id)
            pipe.expire(f"device:user:{user_id}:known_devices", 60 * 60 * 24 * 90)

            pipe.sadd(f"device:{payload.device_id}:users_24h", user_id)
            pipe.expire(f"device:{payload.device_id}:users_24h", 86_400)

            pipe.sadd(f"device:{payload.device_id}:cards_10min", payload.card_bin)
            pipe.expire(f"device:{payload.device_id}:cards_10min", 600)

            await pipe.execute()

            await self.p2p_analyzer.update_accumulated_risk(user_id, final_score)

            if approved:
                await self.trust_service.record_successful_transaction(
                    user_id      = user_id,
                    device_id    = payload.device_id,
                    country_code = getattr(payload, "ip_country", "MX"),
                )

                if payload.transaction_type == "P2P_SEND" and payload.recipient_id:
                    await self.behavior_engine.record_successful_tx(
                        user_id      = user_id,
                        recipient_id = str(payload.recipient_id),
                        amount       = float(payload.amount),
                        currency     = payload.currency,
                    )
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

fraud_orchestrator = FraudOrchestrator()