"""
behavior_engine.py
------------------
Analiza el comportamiento de la transacción actual contra el perfil
histórico del usuario. Reemplaza el behavior_score = 10.0 hardcodeado
por 8 factores reales que distinguen actividad inusual legítima
(quincena, regalo, viaje) de fraude o account takeover.

Factores analizados:
  1. Cambio de perfil reciente     → señal fuerte de account takeover
  2. Login inmediato antes de tx   → posible bot o sesión robada
  3. Hora inusual para ese usuario → comportamiento fuera del patrón
  4. Monto vs promedio histórico   → con excepción por quincena
  5. Cambio de moneda habitual     → posible fraude cross-border
  6. Usuario en primera semana     → período de mayor riesgo estadístico
  7. Destinatario nuevo (P2P)      → primer pago a esta persona
  8. Destinatario frecuente (P2P)  → reducción por relación establecida

Principio de diseño anti falsos positivos:
  - Período de aprendizaje (< 30 días): umbrales más permisivos porque
    aún no tenemos historial confiable del usuario
  - Ventana de quincena: días 1, 15, 16, 30, 31 → montos grandes son
    estadísticamente normales, no se penalizan igual
  - El perfil se cachea en Redis (TTL 5 min) — el motor SOLO LEE
  - Si Redis falla → score neutro de comportamiento, no se penaliza

Tiempo esperado: 5-10ms (lectura de perfil cacheado + lógica en memoria).
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from redis.asyncio import Redis

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
#  Penalizaciones por anomalía de comportamiento                     #
# ------------------------------------------------------------------ #
PENALTY_PROFILE_CHANGE_24H  = 25   # Email o teléfono cambiado en últimas 24h
                                   # → señal de account takeover
PENALTY_FAST_LOGIN_TX       = 15   # Login y tx en < 30 segundos
                                   # → posible bot o sesión robada
PENALTY_UNUSUAL_HOUR        = 15   # Tx fuera del horario habitual del usuario
PENALTY_AMOUNT_10X_AVERAGE  = 35   # Monto > 10x su promedio histórico
PENALTY_AMOUNT_3X_AVERAGE   = 20   # Monto > 3x su promedio histórico
PENALTY_CURRENCY_CHANGE     = 12   # Cambio de moneda habitual
PENALTY_FIRST_WEEK_USER     = 10   # Cuenta con < 7 días de antigüedad
PENALTY_NEW_RECIPIENT       = 10   # Primer pago a este destinatario (P2P)

# ------------------------------------------------------------------ #
#  Reducciones (valores negativos → bajan el score del módulo)       #
# ------------------------------------------------------------------ #
REDUCTION_FREQUENT_RECIPIENT = -12  # 3+ txs exitosas previas con este destinatario
REDUCTION_PAYDAY_WINDOW      = -10  # Monto alto en ventana de quincena
REDUCTION_LEARNING_PERIOD    = -5   # En período de aprendizaje: umbrales más laxos

# ------------------------------------------------------------------ #
#  Constantes de configuración                                       #
# ------------------------------------------------------------------ #
LEARNING_PERIOD_DAYS         = 30   # Días sin historial confiable para un usuario nuevo
FAST_LOGIN_THRESHOLD_SECONDS = 30   # Login → tx en menos de este tiempo → sospechoso
PROFILE_CHANGE_WINDOW_SEC    = 86400  # 24 horas en segundos
FREQUENT_RECIPIENT_MIN_TXS   = 3    # Mínimo de txs previas para considerar "frecuente"
AMOUNT_RATIO_HIGH            = 10.0  # 10x el promedio → penalización máxima
AMOUNT_RATIO_MEDIUM          = 3.0   # 3x el promedio → penalización media


@dataclass
class BehaviorAnalysisResult:
    """
    Resultado del análisis de comportamiento.
    score: acumulado de penalizaciones y reducciones (0-100).
    reason_codes: lista de códigos para auditoría y debugging.
    """
    score: float
    reason_codes: list[str] = field(default_factory=list)
    amount_vs_average_ratio: float = 0.0
    is_unusual_hour: bool = False
    is_new_recipient: bool = False
    in_learning_period: bool = False


@dataclass
class UserBehaviorProfile:
    """
    Perfil conductual del usuario leído desde Redis.
    Escrito por el worker nocturno, nunca calculado en tiempo real.
    """
    avg_transaction_amount: float    # Promedio de monto — últimos 30 días
    std_transaction_amount: float    # Desviación estándar del monto
    typical_hours: list              # Horas del día con actividad habitual [0-23]
    primary_currency: str            # Moneda más usada ("MXN", "USD", etc.)
    account_age_days: int            # Días desde que se creó la cuenta
    last_profile_change_ts: float    # Unix timestamp del último cambio de email/tel
    last_login_ts: float             # Unix timestamp del último login registrado


class BehaviorEngine:
    """
    Compara la transacción actual contra el perfil histórico del usuario
    para detectar comportamiento anómalo.

    Estructura de keys en Redis (escritas por worker nocturno):
      behavior:user:{user_id}:profile
        → JSON con todos los campos de UserBehaviorProfile
        → TTL: 5 minutos (se refresca frecuentemente)

      behavior:user:{user_id}:recipients
        → Hash: {recipient_id: count_de_txs_exitosas}
        → TTL: 180 días

    El campo 'last_login_ts' y 'last_profile_change_ts' debe ser
    actualizado por el servicio de autenticación en tiempo real,
    no solo por el worker nocturno.
    """

    PROFILE_KEY   = "behavior:user:{user_id}:profile"
    RECIPIENT_KEY = "behavior:user:{user_id}:recipients"

    def __init__(self, redis_client: Redis):
        self.redis = redis_client

    # ------------------------------------------------------------------ #
    #  Método principal — llamar dentro del asyncio.gather               #
    # ------------------------------------------------------------------ #

    async def analyze(
        self,
        user_id: str,
        amount: float,
        currency: str,
        transaction_type: str,
        recipient_id: Optional[str] = None,
        current_ts: Optional[datetime] = None,
    ) -> BehaviorAnalysisResult:
        """
        Evalúa el comportamiento de la transacción actual.

        Parámetros:
          user_id          → para buscar el perfil en Redis
          amount           → monto de la transacción
          currency         → moneda de la transacción ("MXN", "USD", etc.)
          transaction_type → "TOP_UP" | "P2P_SEND" | "WITHDRAWAL" | "PAYMENT"
          recipient_id     → solo para P2P_SEND, puede ser None
          current_ts       → inyectable para tests; por defecto datetime.now()
        """
        result = BehaviorAnalysisResult(score=0.0)
        now    = current_ts or datetime.now(timezone.utc)

        # ── Leer perfil del usuario desde Redis ───────────────────────
        profile = await self._get_profile(user_id)

        # ── Período de aprendizaje ────────────────────────────────────
        # Si no hay perfil o la cuenta es muy nueva, aplicamos reducción
        # porque aún no tenemos historial confiable para comparar.
        # Durante este período solo verificamos los factores más críticos
        # (account takeover, bot detection) y saltamos los de patrón.
        in_learning = (
            profile is None
            or profile.account_age_days < LEARNING_PERIOD_DAYS
        )
        if in_learning:
            result.in_learning_period = True
            result.score += REDUCTION_LEARNING_PERIOD
            result.reason_codes.append("LEARNING_PERIOD_ACTIVE")
            profile = profile or self._default_profile()

        # ══════════════════════════════════════════════════════════════
        # FACTOR 1: Cambio de perfil reciente — señal de account takeover
        # ══════════════════════════════════════════════════════════════
        # Si alguien robó la cuenta, lo primero que hace es cambiar el
        # email o teléfono para bloquear al dueño legítimo. Si hubo un
        # cambio en las últimas 24h y ahora hay una tx → muy sospechoso.
        if profile.last_profile_change_ts > 0:
            seconds_since_change = now.timestamp() - profile.last_profile_change_ts
            if 0 < seconds_since_change < PROFILE_CHANGE_WINDOW_SEC:
                result.score += PENALTY_PROFILE_CHANGE_24H
                result.reason_codes.append("PROFILE_CHANGED_LAST_24H")

        # ══════════════════════════════════════════════════════════════
        # FACTOR 2: Login inmediato antes de la tx
        # ══════════════════════════════════════════════════════════════
        # Un humano normal no hace login y en 5 segundos ya está
        # procesando una transacción. Un bot o sesión robada sí.
        # Nota: este check solo aplica cuando tenemos el timestamp de login.
        if profile.last_login_ts > 0:
            seconds_since_login = now.timestamp() - profile.last_login_ts
            if 0 < seconds_since_login < FAST_LOGIN_THRESHOLD_SECONDS:
                result.score += PENALTY_FAST_LOGIN_TX
                result.reason_codes.append(
                    f"TX_WITHIN_{int(seconds_since_login)}S_OF_LOGIN"
                )

        # Los siguientes factores son de patrón conductual.
        # Durante el período de aprendizaje los saltamos porque no
        # tenemos línea base confiable y generaríamos falsos positivos.
        if in_learning:
            result.score = max(0.0, min(100.0, result.score))
            return result

        # ══════════════════════════════════════════════════════════════
        # FACTOR 3: Hora inusual para este usuario
        # ══════════════════════════════════════════════════════════════
        # Cada usuario tiene un patrón de horario. Si sus typical_hours
        # son [9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20] y ahora
        # opera a las 3am → comportamiento fuera del patrón.
        current_hour = now.hour
        if profile.typical_hours and current_hour not in profile.typical_hours:
            result.is_unusual_hour = True
            result.score += PENALTY_UNUSUAL_HOUR
            result.reason_codes.append(f"UNUSUAL_HOUR_{current_hour}H")

        # ══════════════════════════════════════════════════════════════
        # FACTOR 4: Monto vs promedio histórico
        # ══════════════════════════════════════════════════════════════
        # Comparamos el monto actual contra el promedio de los últimos
        # 30 días. Si es 3x o 10x mayor → anomalía.
        # EXCEPCIÓN: si es día de quincena, un monto alto es normal.
        if profile.avg_transaction_amount > 0:
            ratio = amount / profile.avg_transaction_amount
            result.amount_vs_average_ratio = ratio

            if ratio > AMOUNT_RATIO_HIGH:
                # 10x el promedio: penalización fuerte, sin excepción
                # Un regalo no justifica 10x — sí justifica 3x
                result.score += PENALTY_AMOUNT_10X_AVERAGE
                result.reason_codes.append(f"AMOUNT_{int(ratio)}X_AVERAGE")

            elif ratio > AMOUNT_RATIO_MEDIUM:
                # 3x el promedio: verificar si es quincena antes de penalizar
                if self._is_payday_window(now):
                    # Es día de quincena → monto grande es esperado
                    result.score += REDUCTION_PAYDAY_WINDOW
                    result.reason_codes.append("PAYDAY_WINDOW_REDUCTION")
                else:
                    result.score += PENALTY_AMOUNT_3X_AVERAGE
                    result.reason_codes.append(f"AMOUNT_{int(ratio)}X_AVERAGE")

        # ══════════════════════════════════════════════════════════════
        # FACTOR 5: Cambio de moneda habitual
        # ══════════════════════════════════════════════════════════════
        # Si el usuario siempre operó en MXN y ahora manda en USD →
        # puede ser un viaje legítimo o un fraude cross-border.
        # El geo_analyzer también lo detectará si la IP es extranjera,
        # así que esta penalización es moderada.
        if profile.primary_currency and currency != profile.primary_currency:
            result.score += PENALTY_CURRENCY_CHANGE
            result.reason_codes.append(
                f"CURRENCY_CHANGE_{profile.primary_currency}_TO_{currency}"
            )

        # ══════════════════════════════════════════════════════════════
        # FACTOR 6: Usuario en primera semana
        # ══════════════════════════════════════════════════════════════
        # Estadísticamente los primeros 7 días son los de mayor riesgo.
        # Los defraudadores crean cuentas y actúan rápido antes de ser
        # detectados. Este factor es distinto al período de aprendizaje:
        # no impide el análisis de patrón, solo agrega una penalización.
        if profile.account_age_days < 7:
            result.score += PENALTY_FIRST_WEEK_USER
            result.reason_codes.append(
                f"FIRST_WEEK_USER_DAY_{profile.account_age_days}"
            )

        # ══════════════════════════════════════════════════════════════
        # FACTOR 7 y 8: Destinatario nuevo o frecuente (solo P2P)
        # ══════════════════════════════════════════════════════════════
        if transaction_type == "P2P_SEND" and recipient_id:
            tx_count = await self._get_recipient_tx_count(user_id, recipient_id)
            result.is_new_recipient = tx_count == 0

            if tx_count == 0:
                result.score += PENALTY_NEW_RECIPIENT
                result.reason_codes.append("P2P_NEW_RECIPIENT_FIRST_TX")

            elif tx_count >= FREQUENT_RECIPIENT_MIN_TXS:
                result.score += REDUCTION_FREQUENT_RECIPIENT
                result.reason_codes.append(
                    f"P2P_FREQUENT_RECIPIENT_{tx_count}_TXS"
                )

        # Clampear entre 0 y 100
        result.score = max(0.0, min(100.0, result.score))

        logger.debug(
            f"[Behavior] user={user_id}  score={result.score:.1f}  "
            f"amount_ratio={result.amount_vs_average_ratio:.1f}x  "
            f"codes={result.reason_codes}"
        )
        return result

    # ------------------------------------------------------------------ #
    #  Detección de ventana de quincena                                  #
    # ------------------------------------------------------------------ #

    def _is_payday_window(self, dt: datetime) -> bool:
        """
        Retorna True si el día actual es una fecha típica de pago en México.
        Días: 1 (inicio de mes), 15 y 16 (quincena), 30 y 31 (fin de mes).

        Esto evita penalizar transacciones grandes en días donde
        el usuario naturalmente tiene más dinero disponible y gasta más.
        """
        return dt.day in {1, 15, 16, 30, 31}

    # ------------------------------------------------------------------ #
    #  Lectura de Redis                                                  #
    # ------------------------------------------------------------------ #

    async def _get_profile(self, user_id: str) -> Optional[UserBehaviorProfile]:
        """
        Lee el perfil conductual del usuario desde Redis.
        Retorna None si no existe (usuario nuevo o Redis caído).
        """
        key = self.PROFILE_KEY.format(user_id=user_id)
        try:
            raw = await self.redis.get(key)
            if not raw:
                return None

            data = json.loads(raw)
            return UserBehaviorProfile(
                avg_transaction_amount = data.get("avg_amount", 0.0),
                std_transaction_amount = data.get("std_amount", 0.0),
                typical_hours          = data.get("typical_hours", list(range(8, 23))),
                primary_currency       = data.get("primary_currency", "MXN"),
                account_age_days       = data.get("account_age_days", 0),
                last_profile_change_ts = data.get("last_profile_change_ts", 0.0),
                last_login_ts          = data.get("last_login_ts", 0.0),
            )
        except Exception as e:
            logger.error(f"[Behavior] Error leyendo perfil user={user_id}: {e}")
            return None

    async def _get_recipient_tx_count(
        self, user_id: str, recipient_id: str
    ) -> int:
        """
        Retorna el número de transacciones P2P exitosas previas
        entre este emisor y este destinatario específico.
        """
        key = self.RECIPIENT_KEY.format(user_id=user_id)
        try:
            raw = await self.redis.hget(key, recipient_id)
            return int(raw) if raw else 0
        except Exception as e:
            logger.error(f"[Behavior] Error leyendo recipient count: {e}")
            return 0

    # ------------------------------------------------------------------ #
    #  Escritura — solo desde workers en background                      #
    # ------------------------------------------------------------------ #

    async def record_successful_tx(
        self,
        user_id: str,
        recipient_id: Optional[str],
        amount: float,
        currency: str,
    ) -> None:
        """
        Actualiza el contador de transacciones exitosas con un destinatario.
        Se llama en background DESPUÉS de enviar la respuesta al Wallet.
        El perfil completo (avg_amount, typical_hours, etc.) lo actualiza
        el worker nocturno desde la base de datos — aquí solo el contador
        de destinatarios porque necesita ser en tiempo real.
        """
        if not recipient_id:
            return
        key = self.RECIPIENT_KEY.format(user_id=user_id)
        try:
            await self.redis.hincrby(key, recipient_id, 1)
            await self.redis.expire(key, 60 * 60 * 24 * 180)
        except Exception as e:
            logger.error(
                f"[Behavior] Error registrando tx exitosa user={user_id}: {e}"
            )

    async def update_login_timestamp(self, user_id: str) -> None:
        """
        Actualiza el timestamp del último login del usuario.
        Llamar desde el servicio de autenticación justo después del login.
        Este dato es crítico para detectar bots (Factor 2).
        """
        key = self.PROFILE_KEY.format(user_id=user_id)
        try:
            raw = await self.redis.get(key)
            if raw:
                data = json.loads(raw)
                data["last_login_ts"] = datetime.now(timezone.utc).timestamp()
                await self.redis.setex(key, 300, json.dumps(data))
        except Exception as e:
            logger.error(
                f"[Behavior] Error actualizando login ts user={user_id}: {e}"
            )

    async def update_profile_change_timestamp(self, user_id: str) -> None:
        """
        Actualiza el timestamp del último cambio de perfil (email o teléfono).
        Llamar desde el servicio de perfil cuando el usuario modifica datos.
        Este dato es crítico para detectar account takeover (Factor 1).
        """
        key = self.PROFILE_KEY.format(user_id=user_id)
        try:
            raw = await self.redis.get(key)
            if raw:
                data = json.loads(raw)
                data["last_profile_change_ts"] = (
                    datetime.now(timezone.utc).timestamp()
                )
                await self.redis.setex(key, 300, json.dumps(data))
        except Exception as e:
            logger.error(
                f"[Behavior] Error actualizando profile change ts user={user_id}: {e}"
            )

    # ------------------------------------------------------------------ #
    #  Perfil por defecto                                                #
    # ------------------------------------------------------------------ #

    def _default_profile(self) -> UserBehaviorProfile:
        """
        Perfil para usuarios sin historial en Redis.
        Valores conservadores que evitan penalizaciones injustas.
        """
        return UserBehaviorProfile(
            avg_transaction_amount = 0.0,
            std_transaction_amount = 0.0,
            typical_hours          = list(range(7, 23)),
            primary_currency       = "MXN",
            account_age_days       = 0,
            last_profile_change_ts = 0.0,
            last_login_ts          = 0.0,
        )