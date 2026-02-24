"""
trust_score.py
--------------
Calcula el Trust Score de un usuario y lo convierte en una REDUCCIÓN
del Risk Score final. Es el mecanismo principal para evitar falsos
positivos en usuarios legítimos con buen historial.

Reducción máxima posible: -25 puntos sobre el Risk Score final.
Ejemplo: usuario con score calculado de 45 (zona CHALLENGE) pero con
Trust Reduction de -20 queda en 25 → ACTION_APPROVE sin fricción.

Principio de diseño:
  - Los datos del perfil se pre-calculan en un worker nocturno y se
    cachean en Redis. El motor SOLO LEE durante la evaluación.
  - Si Redis no tiene datos del usuario (es nuevo), retorna perfil
    neutro con reducción = 0. No penaliza, simplemente no ayuda.
  - Cada factor de reducción se registra en 'breakdown' para que
    el panel de analistas pueda ver por qué se redujo el score.

Flujo de datos:
  Worker nocturno → calcula perfil desde DB → escribe en Redis (TTL 6h)
  Motor antifraude → lee de Redis → aplica reducción al score final

Tiempo esperado: 2-5ms (mget en Redis, igual que blacklist).
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Optional

from redis.asyncio import Redis

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
#  Constantes de reducción por factor de confianza                   #
#  Todos son negativos: reducen el Risk Score final                  #
# ------------------------------------------------------------------ #

REDUCTION_LONG_HISTORY    = -15   # 6+ meses sin incidentes confirmados
REDUCTION_MEDIUM_HISTORY  = -8    # 2-5 meses sin incidentes
REDUCTION_KYC_FULL        = -7    # KYC completo: documento + biometría
REDUCTION_KYC_BASIC       = -3    # KYC básico: solo email + teléfono verificados
REDUCTION_MFA_ACTIVE      = -5    # Usuario tiene MFA (TOTP o biometría) habilitado
REDUCTION_FREQUENT_DEVICE = -5    # Dispositivo usado > 10 veces exitosamente
REDUCTION_TRUSTED_COUNTRY = -3    # País de operación está en historial habitual

MAX_TOTAL_REDUCTION       = -25   # Límite absoluto — nunca reducir más de 25 pts


@dataclass
class TrustProfile:
    """
    Perfil de confianza calculado para un usuario.

    trust_reduction: valor negativo que se suma al Risk Score final.
    breakdown: desglose de cada factor para auditoría y debugging.
    """
    user_id: str
    trust_reduction: int                          # Ej: -20 → reduce score en 20 pts
    account_age_days: int
    kyc_level: str                                # "none" | "basic" | "full"
    mfa_active: bool
    incident_free_months: int
    is_frequent_device: bool
    country_in_history: bool
    breakdown: dict = field(default_factory=dict)


class TrustScoreService:
    """
    Lee el perfil de confianza del usuario desde Redis y calcula
    cuánto debe reducirse su Risk Score final.

    Estructura de keys en Redis (escritas por el worker nocturno):
      trust:user:{user_id}:account_age_days      → int  (ej. "245")
      trust:user:{user_id}:kyc_level             → str  (ej. "full")
      trust:user:{user_id}:mfa_active            → "1" | "0"
      trust:user:{user_id}:incident_free_months  → int  (ej. "8")
      trust:user:{user_id}:total_successful_tx   → int  (ej. "312")
      trust:user:{user_id}:frequent_devices      → JSON list de device_ids
      trust:user:{user_id}:frequent_countries    → JSON list de country_codes

    Ejemplo de lo que el worker nocturno escribe:
      SET trust:user:abc123:kyc_level "full" EX 21600
      SET trust:user:abc123:mfa_active "1" EX 21600
      SET trust:user:abc123:incident_free_months "8" EX 21600
      SET trust:user:abc123:frequent_devices '["dev_x1","dev_y2"]' EX 21600
    """

    KEY_PREFIX = "trust:user"

    def __init__(self, redis_client: Redis):
        self.redis = redis_client

    # ------------------------------------------------------------------ #
    #  Método principal — llamar dentro del asyncio.gather               #
    # ------------------------------------------------------------------ #

    async def get_trust_profile(
        self,
        user_id: str,
        device_id: str,
        country_code: Optional[str] = None,
    ) -> TrustProfile:
        """
        Lee el perfil de confianza del usuario y calcula la reducción.

        Retorna perfil neutro (reducción = 0) si:
          - El usuario no tiene datos en Redis (es nuevo)
          - Redis falla (fail open: no castigamos por error de infra)

        Parámetros:
          user_id      → para buscar los keys del perfil
          device_id    → para verificar si es un dispositivo frecuente
          country_code → para verificar si el país está en historial
                         (viene del análisis GeoIP en el orquestador)
        """
        prefix = f"{self.KEY_PREFIX}:{user_id}"

        # Todos los keys del perfil en un solo mget
        keys = [
            f"{prefix}:account_age_days",
            f"{prefix}:kyc_level",
            f"{prefix}:mfa_active",
            f"{prefix}:incident_free_months",
            f"{prefix}:total_successful_tx",
            f"{prefix}:frequent_devices",
            f"{prefix}:frequent_countries",
        ]

        try:
            results = await self.redis.mget(*keys)
        except Exception as e:
            logger.error(f"[TrustScore] Redis error para user={user_id}: {e}")
            return self._neutral_profile(user_id)

        (
            raw_age, raw_kyc, raw_mfa,
            raw_incident_free, raw_total_tx,
            raw_devices, raw_countries,
        ) = results

        # ── Parsear valores con defaults seguros ──────────────────────
        account_age_days     = int(raw_age)           if raw_age           else 0
        kyc_level            = raw_kyc.decode()       if raw_kyc           else "none"
        mfa_active           = raw_mfa == b"1"        if raw_mfa           else False
        incident_free_months = int(raw_incident_free) if raw_incident_free else 0

        # ── Verificar si el device_id es un dispositivo frecuente ─────
        is_frequent_device = False
        if raw_devices:
            try:
                frequent_devices   = json.loads(raw_devices)
                is_frequent_device = device_id in frequent_devices
            except (json.JSONDecodeError, TypeError):
                pass

        # ── Verificar si el país está en el historial habitual ────────
        country_in_history = False
        if country_code and raw_countries:
            try:
                frequent_countries = json.loads(raw_countries)
                country_in_history = country_code in frequent_countries
            except (json.JSONDecodeError, TypeError):
                pass

        return self._calculate_reduction(
            user_id=user_id,
            account_age_days=account_age_days,
            kyc_level=kyc_level,
            mfa_active=mfa_active,
            incident_free_months=incident_free_months,
            is_frequent_device=is_frequent_device,
            country_in_history=country_in_history,
        )

    # ------------------------------------------------------------------ #
    #  Cálculo de reducción                                              #
    # ------------------------------------------------------------------ #

    def _calculate_reduction(
        self,
        user_id: str,
        account_age_days: int,
        kyc_level: str,
        mfa_active: bool,
        incident_free_months: int,
        is_frequent_device: bool,
        country_in_history: bool,
    ) -> TrustProfile:
        """
        Aplica cada factor de reducción y suma el total.
        Respeta el límite MAX_TOTAL_REDUCTION (-25 pts).
        Registra cada factor en breakdown para auditoría.
        """
        breakdown = {}
        total = 0

        # ── Factor 1: Historial sin incidentes ────────────────────────
        # El más importante: recompensa a usuarios con trayectoria limpia
        if incident_free_months >= 6:
            breakdown["long_history"]   = REDUCTION_LONG_HISTORY
            total                      += REDUCTION_LONG_HISTORY
        elif incident_free_months >= 2:
            breakdown["medium_history"] = REDUCTION_MEDIUM_HISTORY
            total                      += REDUCTION_MEDIUM_HISTORY

        # ── Factor 2: Nivel de KYC ────────────────────────────────────
        # KYC completo = identidad verificada con documento + biometría
        if kyc_level == "full":
            breakdown["kyc_full"]  = REDUCTION_KYC_FULL
            total                 += REDUCTION_KYC_FULL
        elif kyc_level == "basic":
            breakdown["kyc_basic"] = REDUCTION_KYC_BASIC
            total                 += REDUCTION_KYC_BASIC

        # ── Factor 3: MFA activo ──────────────────────────────────────
        # Usuario que configuró MFA tiene mayor conciencia de seguridad
        if mfa_active:
            breakdown["mfa_active"] = REDUCTION_MFA_ACTIVE
            total                  += REDUCTION_MFA_ACTIVE

        # ── Factor 4: Dispositivo frecuente ───────────────────────────
        # Está operando desde un dispositivo con historial exitoso
        if is_frequent_device:
            breakdown["frequent_device"] = REDUCTION_FREQUENT_DEVICE
            total                       += REDUCTION_FREQUENT_DEVICE

        # ── Factor 5: País en historial habitual ──────────────────────
        # Ya operó desde este país antes → no es un país "nuevo" riesgoso
        if country_in_history:
            breakdown["trusted_country"] = REDUCTION_TRUSTED_COUNTRY
            total                       += REDUCTION_TRUSTED_COUNTRY

        # Nunca reducir más que el límite absoluto
        final_reduction = max(total, MAX_TOTAL_REDUCTION)

        logger.debug(
            f"[TrustScore] user={user_id}  "
            f"reduction={final_reduction}  breakdown={breakdown}"
        )

        return TrustProfile(
            user_id=user_id,
            trust_reduction=final_reduction,
            account_age_days=account_age_days,
            kyc_level=kyc_level,
            mfa_active=mfa_active,
            incident_free_months=incident_free_months,
            is_frequent_device=is_frequent_device,
            country_in_history=country_in_history,
            breakdown=breakdown,
        )

    def _neutral_profile(self, user_id: str) -> TrustProfile:
        """
        Perfil neutro para usuarios nuevos o cuando Redis no responde.
        Reducción = 0: no ayuda ni perjudica al score final.
        """
        return TrustProfile(
            user_id=user_id,
            trust_reduction=0,
            account_age_days=0,
            kyc_level="none",
            mfa_active=False,
            incident_free_months=0,
            is_frequent_device=False,
            country_in_history=False,
            breakdown={},
        )

    # ------------------------------------------------------------------ #
    #  Métodos de escritura — solo desde workers en background           #
    #  NUNCA llamar durante el flujo principal del motor                 #
    # ------------------------------------------------------------------ #

    async def record_successful_transaction(
        self,
        user_id: str,
        device_id: str,
        country_code: str,
    ) -> None:
        """
        Incrementa el contador de transacciones exitosas.
        Se llama en background DESPUÉS de enviar la respuesta al Wallet.
        """
        prefix = f"{self.KEY_PREFIX}:{user_id}"
        try:
            pipe = self.redis.pipeline()
            pipe.incr(f"{prefix}:total_successful_tx")
            pipe.expire(f"{prefix}:total_successful_tx", 60 * 60 * 24 * 180)
            await pipe.execute()
        except Exception as e:
            logger.error(
                f"[TrustScore] Error registrando tx exitosa user={user_id}: {e}"
            )

    async def reset_incident_free_counter(self, user_id: str) -> None:
        """
        Reinicia el contador de meses sin incidentes.
        Llamar desde el panel cuando un analista confirma fraude real
        (distingue de falso positivo — en ese caso NO llamar esto).
        """
        key = f"{self.KEY_PREFIX}:{user_id}:incident_free_months"
        try:
            await self.redis.set(key, "0")
            logger.info(
                f"[TrustScore] Contador reiniciado para user={user_id}"
            )
        except Exception as e:
            logger.error(
                f"[TrustScore] Error reiniciando contador user={user_id}: {e}"
            )