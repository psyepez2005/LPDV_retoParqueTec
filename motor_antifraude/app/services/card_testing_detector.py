"""
card_testing_detector.py
------------------------
Detecta el patrón "card testing": un atacante que obtuvo datos de
tarjetas roba hace primero micro-transacciones para verificar que
la tarjeta es válida, y luego ejecuta el cargo grande.

Complementa el BehaviorEngine (que compara contra el promedio
histórico de 30 días). Este módulo detecta el ataque activo
en tiempo real dentro de la misma hora, por BIN específico.

Redis:
  card_test:{device_id}:{card_bin}:amounts → LIST de montos (últimas 10 tx, 1hr)
  card_test:{card_bin}:rate_10min          → COUNTER de requests en 10min
"""

import logging
import time
from dataclasses import dataclass, field

from app.infrastructure.cache.redis_client import redis_manager

logger = logging.getLogger(__name__)

_AMOUNTS_TTL    = 3_600   # 1 hora
_RATE_TTL       = 600     # 10 minutos
_PROBE_THRESHOLD = 3      # mínimo N micro-transacciones para activar la regla
_PROBE_MAX_AMOUNT = 10.0  # monto máximo para considerar "micro-transacción"
_LARGE_THRESHOLD  = 200.0 # monto que activa el flag si viene después de micros
_RAPID_THRESHOLD  = 5     # 5+ transacciones en 10min con el mismo BIN


@dataclass
class CardTestingResult:
    penalty:      int       = 0
    reason_codes: list[str] = field(default_factory=list)


class CardTestingDetector:
    """
    Mantiene una ventana deslizante de montos por (device_id, card_bin)
    para detectar el patrón micro → grande (card testing) y ataques
    rápidos de carding.
    """

    async def check(
        self,
        device_id: str,
        card_bin:  str,
        amount:    float,
    ) -> CardTestingResult:
        result    = CardTestingResult()
        redis     = redis_manager.client
        amounts_key = f"card_test:{device_id}:{card_bin}:amounts"
        rate_key    = f"card_test:{card_bin}:rate_10min"

        try:
            pipe = redis.pipeline()
            # Agregar monto actual al histórico de la ventana
            pipe.lpush(amounts_key, str(amount))
            pipe.ltrim(amounts_key, 0, 9)        # solo últimas 10 transacciones
            pipe.expire(amounts_key, _AMOUNTS_TTL)
            # Contador rápido por BIN en 10min
            pipe.incr(rate_key)
            pipe.expire(rate_key, _RATE_TTL)
            results = await pipe.execute()

            rapid_count = results[3]  # valor del INCR

            # ── Regla 1: Carding rápido (muchos requests al mismo BIN) ──
            if rapid_count >= _RAPID_THRESHOLD:
                result.penalty += 35
                result.reason_codes.append(
                    f"RAPID_BIN_PROBE_{rapid_count}_IN_10MIN"
                )
                logger.warning(
                    f"[CardTesting] Rapid probe card_bin={card_bin} "
                    f"count={rapid_count}"
                )

            # ── Regla 2: Micro → Grande (card testing clásico) ──────────
            if amount >= _LARGE_THRESHOLD:
                # Obtener el historial (sin el monto actual que acabamos de pushear)
                raw_amounts = await redis.lrange(amounts_key, 1, -1)
                prev_amounts = [float(a) for a in raw_amounts if a]

                if len(prev_amounts) >= _PROBE_THRESHOLD:
                    micro_count = sum(
                        1 for a in prev_amounts if a <= _PROBE_MAX_AMOUNT
                    )
                    if micro_count >= _PROBE_THRESHOLD:
                        result.penalty += 40
                        result.reason_codes.append(
                            f"CARD_TESTING_PATTERN_{micro_count}_PROBES"
                        )
                        logger.warning(
                            f"[CardTesting] Pattern detected device={device_id} "
                            f"bin={card_bin} probes={micro_count} "
                            f"large_amount={amount}"
                        )

        except Exception as e:
            logger.error(f"[CardTesting] Redis error: {e}")

        return result


card_testing_detector = CardTestingDetector()
