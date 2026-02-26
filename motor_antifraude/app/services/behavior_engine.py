"""
MOTOR DE ANÁLISIS CONDUCTUAL (BehaviorEngine)
---------------------------------------------
Este motor determina si una transacción es "extraña" comparándola con el 
pasado del usuario. No es una lista negra, sino un análisis de hábitos.

Puntos clave:
1. Resiliencia: Si Redis falla, el motor devuelve un score neutro (no bloquea).
2. Velocidad: Diseñado para responder en < 10ms leyendo de caché.
3. Inteligencia: Diferencia entre un robo de cuenta y un gasto normal de quincena.
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
PENALTY_UNUSUAL_HOUR        = 15   # Transacción en hora fuera del rango habitual
PENALTY_AMOUNT_10X_AVERAGE  = 35   # Monto > 10x su promedio histórico
PENALTY_AMOUNT_3X_AVERAGE   = 20   # Monto > 3x su promedio histórico
PENALTY_CURRENCY_CHANGE     = 12   # Cambio de moneda habitual
PENALTY_FIRST_WEEK_USER     = 10   # Cuenta con < 7 días de antigüedad
PENALTY_NEW_RECIPIENT       = 10   # Primer pago a este destinatario (P2P)

REDUCTION_FREQUENT_RECIPIENT = -12  
REDUCTION_PAYDAY_WINDOW      = -10  
REDUCTION_LEARNING_PERIOD    = -5  

LEARNING_PERIOD_DAYS         = 30   
FAST_LOGIN_THRESHOLD_SECONDS = 30   
PROFILE_CHANGE_WINDOW_SEC    = 86400 
FREQUENT_RECIPIENT_MIN_TXS   = 3    
AMOUNT_RATIO_HIGH            = 10.0  
AMOUNT_RATIO_MEDIUM          = 3.0   


@dataclass
class BehaviorAnalysisResult:
 
    score: float
    reason_codes: list[str] = field(default_factory=list)
    amount_vs_average_ratio: float = 0.0
    is_unusual_hour: bool = False
    is_new_recipient: bool = False
    in_learning_period: bool = False


@dataclass
class UserBehaviorProfile:
   
    avg_transaction_amount: float   
    std_transaction_amount: float    
    typical_hours: list              
    primary_currency: str            
    account_age_days: int            
    last_profile_change_ts: float    
    last_login_ts: float             


class BehaviorEngine:
    
    PROFILE_KEY   = "behavior:user:{user_id}:profile"
    RECIPIENT_KEY = "behavior:user:{user_id}:recipients"

    def __init__(self, redis_client: Redis):
        self.redis = redis_client

    async def analyze(
        self,
        user_id: str,
        amount: float,
        currency: str,
        transaction_type: str,
        recipient_id: Optional[str] = None,
        current_ts: Optional[datetime] = None,
    ) -> BehaviorAnalysisResult:
        
        result = BehaviorAnalysisResult(score=0.0)
        now    = current_ts or datetime.now(timezone.utc)

        profile = await self._get_profile(user_id)

        in_learning = (
            profile is None
            or profile.account_age_days < LEARNING_PERIOD_DAYS
        )
        if in_learning:
            result.in_learning_period = True
            result.score += REDUCTION_LEARNING_PERIOD
            result.reason_codes.append("LEARNING_PERIOD_ACTIVE")
            profile = profile or self._default_profile()

        
        if profile.last_profile_change_ts > 0:
            seconds_since_change = now.timestamp() - profile.last_profile_change_ts
            if 0 < seconds_since_change < PROFILE_CHANGE_WINDOW_SEC:
                result.score += PENALTY_PROFILE_CHANGE_24H
                result.reason_codes.append("PROFILE_CHANGED_LAST_24H")

        
        if profile.last_login_ts > 0:
            seconds_since_login = now.timestamp() - profile.last_login_ts
            if 0 < seconds_since_login < FAST_LOGIN_THRESHOLD_SECONDS:
                result.score += PENALTY_FAST_LOGIN_TX
                result.reason_codes.append(
                    f"TX_WITHIN_{int(seconds_since_login)}S_OF_LOGIN"
                )

        if in_learning:
            result.score = max(0.0, min(100.0, result.score))
            return result


        current_hour = now.hour
        if profile.typical_hours and current_hour not in profile.typical_hours:
            result.is_unusual_hour = True
            result.score += PENALTY_UNUSUAL_HOUR
            result.reason_codes.append(f"UNUSUAL_HOUR_{current_hour}H")

        if profile.avg_transaction_amount > 0:
            ratio = amount / profile.avg_transaction_amount
            result.amount_vs_average_ratio = ratio

            if ratio > AMOUNT_RATIO_HIGH:
                result.score += PENALTY_AMOUNT_10X_AVERAGE
                result.reason_codes.append(f"AMOUNT_{int(ratio)}X_AVERAGE")

            elif ratio > AMOUNT_RATIO_MEDIUM:
                if self._is_payday_window(now):
                    result.score += REDUCTION_PAYDAY_WINDOW
                    result.reason_codes.append("PAYDAY_WINDOW_REDUCTION")
                else:
                    result.score += PENALTY_AMOUNT_3X_AVERAGE
                    result.reason_codes.append(f"AMOUNT_{int(ratio)}X_AVERAGE")

        if profile.primary_currency and currency != profile.primary_currency:
            result.score += PENALTY_CURRENCY_CHANGE
            result.reason_codes.append(
                f"CURRENCY_CHANGE_{profile.primary_currency}_TO_{currency}"
            )

        if profile.account_age_days < 7:
            result.score += PENALTY_FIRST_WEEK_USER
            result.reason_codes.append(
                f"FIRST_WEEK_USER_DAY_{profile.account_age_days}"
            )

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

        result.score = max(0.0, min(100.0, result.score))

        logger.debug(
            f"[Behavior] user={user_id}  score={result.score:.1f}  "
            f"amount_ratio={result.amount_vs_average_ratio:.1f}x  "
            f"codes={result.reason_codes}"
        )
        return result

    def _is_payday_window(self, dt: datetime) -> bool:
        """
        Retorna True si el día actual es una fecha típica de pago en México.
        Días: 1 (inicio de mes), 15 y 16 (quincena), 30 y 31 (fin de mes).

        Esto evita penalizar transacciones grandes en días donde
        el usuario naturalmente tiene más dinero disponible y gasta más.
        """
        return dt.day in {1, 15, 16, 30, 31}

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