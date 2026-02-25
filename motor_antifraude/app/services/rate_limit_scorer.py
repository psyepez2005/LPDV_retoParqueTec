"""
rate_limit_scorer.py
--------------------
Scoring por velocidad de requests en tiempo real.

Usa una sliding window en Redis para detectar cuando
un mismo usuario o IP envía muchas peticiones en poco tiempo.
Esto penaliza bots, scripts de prueba masivos y ataques
de credential stuffing que hacen muchas transacciones seguidas.
"""

import logging
from typing import Optional

from app.infrastructure.cache.redis_client import redis_manager

logger = logging.getLogger(__name__)

# Ventanas de tiempo y umbrales
_WINDOW_SECONDS   = 60   # Ventana deslizante de 60 segundos
_USER_WINDOW      = 300  # Ventana más amplia para usuario (5 min)

# Penalizaciones por requests en la ventana de 60s (por IP)
_IP_THRESHOLDS = [
    (11, 45, "IP_RATE_EXTREME"),   # 11+  → +45 pts
    (7,  25, "IP_RATE_HIGH"),      # 7-10 → +25 pts
    (4,  10, "IP_RATE_ELEVATED"),  # 4-6  → +10 pts
]

# Penalizaciones por requests en la ventana de 5 min (por usuario)
_USER_THRESHOLDS = [
    (20, 40, "USER_RATE_EXTREME"),  # 20+  → +40 pts
    (10, 20, "USER_RATE_HIGH"),     # 10-19 → +20 pts
    (5,  8,  "USER_RATE_ELEVATED"), # 5-9  → +8 pts
]


class RateLimitScorer:
    """
    Scorer de rate-limiting en tiempo real.
    Usa INCR + EXPIRE en Redis — sin librerías adicionales.
    Si Redis falla, devuelve (0, []) para no bloquear la evaluación.
    """

    async def score(
        self,
        user_id:    str,
        ip_address: str,
    ) -> tuple[int, list[str]]:
        """
        Registra el request actual y calcula la penalización.

        Returns:
            (penalty_score, reason_codes)
        """
        redis = redis_manager.client

        try:
            ip_key   = f"rate:ip:{ip_address}"
            user_key = f"rate:user:{user_id}"

            # Incrementar contadores y establecer TTL si es la primera vez
            ip_pipe = redis.pipeline()
            ip_pipe.incr(ip_key)
            ip_pipe.expire(ip_key, _WINDOW_SECONDS)
            ip_pipe.incr(user_key)
            ip_pipe.expire(user_key, _USER_WINDOW)
            results = await ip_pipe.execute()

            ip_count   = results[0]  # valor tras INCR
            user_count = results[2]

        except Exception as e:
            logger.warning(f"[RateLimitScorer] Redis error: {e}")
            return 0, []

        penalty      = 0
        reason_codes = []

        # Evaluar penalización por IP
        for threshold, pts, code in _IP_THRESHOLDS:
            if ip_count >= threshold:
                penalty += pts
                reason_codes.append(code)
                break

        # Evaluar penalización por usuario
        for threshold, pts, code in _USER_THRESHOLDS:
            if user_count >= threshold:
                penalty += pts
                reason_codes.append(code)
                break

        if penalty > 0:
            logger.info(
                f"[RateLimitScorer] ip={ip_address} ip_req={ip_count}  "
                f"user={user_id} user_req={user_count}  penalty={penalty}"
            )

        return min(penalty, 60), reason_codes   # Cap en 60 pts


# Singleton
rate_limit_scorer = RateLimitScorer()
