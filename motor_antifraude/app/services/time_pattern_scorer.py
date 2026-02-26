"""
time_pattern_scorer.py
----------------------
Detecta transacciones en horarios donde el usuario nunca ha sido activo.

Complementa el Factor 3 del BehaviorEngine (que usa typical_hours del
perfil escrito por el worker nocturno). Este módulo usa un bitmap en
tiempo real que crece con cada petición al motor.

Redis:
  timepattern:user:{user_id}:bitmap  → STRING de 24 bits (1 bit por hora)
  timepattern:user:{user_id}:tx_count → COUNTER de transacciones totales

Lógica:
  - Los primeros 10 requests del usuario no generan penalización
    (periodo de calibración — sin datos suficientes para comparar)
  - A partir de la tx #11: si el bit de la hora actual es 0 → hora nueva
  - Después de evaluar, siempre seteamos el bit de la hora actual
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.infrastructure.cache.redis_client import redis_manager

logger = logging.getLogger(__name__)

_BITMAP_TTL    = 60 * 60 * 24 * 90   # 90 días
_COUNT_TTL     = 60 * 60 * 24 * 90
_MIN_TX_BEFORE_PENALIZING = 10        # calibración mínima


@dataclass
class TimePatternResult:
    penalty:      int       = 0
    reason_codes: list[str] = field(default_factory=list)


class TimePatternScorer:
    """
    Mantiene un bitmap de 24 bits por usuario que registra en qué
    horas del día ha sido activo históricamente.

    No depende de perfil nocturno: se actualiza en cada request.
    """

    async def score(
        self,
        user_id:      str,
    ) -> TimePatternResult:
        result = TimePatternResult()
        redis  = redis_manager.client
        now    = datetime.now(timezone.utc)
        hour   = now.hour

        bitmap_key = f"timepattern:user:{user_id}:bitmap"
        count_key  = f"timepattern:user:{user_id}:tx_count"

        try:
            # Leer el bit de la hora actual y el contador total
            bit_active, raw_count = await redis.execute_command(  # type: ignore
                "BITFIELD", bitmap_key,
                "GET", "u1", str(hour),
            ), await redis.get(count_key)

            # bit_active es una lista con el resultado de BITFIELD
            if isinstance(bit_active, list) and len(bit_active) > 0:
                bit_value = bit_active[0]
            else:
                bit_value = 0

            tx_count = int(raw_count) if raw_count else 0

            # Solo penalizamos cuando tenemos suficiente historial
            if tx_count >= _MIN_TX_BEFORE_PENALIZING:
                if bit_value == 0:
                    # Hora nunca activa antes → comportamiento inusual
                    result.penalty += 15
                    result.reason_codes.append(f"UNUSUAL_HOUR_{hour}H_NEVER_ACTIVE")
                    logger.info(
                        f"[TimePattern] User={user_id} active at hour={hour} "
                        f"for first time (tx_count={tx_count})"
                    )


            # Actualizar: setear el bit de la hora actual + incrementar contador
            pipe = redis.pipeline()
            pipe.execute_command("SETBIT", bitmap_key, str(hour), "1")
            pipe.expire(bitmap_key, _BITMAP_TTL)
            pipe.incr(count_key)
            pipe.expire(count_key, _COUNT_TTL)
            await pipe.execute()

        except Exception as e:
            logger.error(f"[TimePattern] Redis error: {e}")

        return result


time_pattern_scorer = TimePatternScorer()
