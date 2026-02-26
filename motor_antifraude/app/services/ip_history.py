"""
ip_history.py
-------------
Detecta saltos imposibles de país de IP por usuario.

Guarda la última IP conocida del usuario con timestamp en Redis.
Si el país de la IP cambia en < 30min → señal de VPN o account takeover.
Si cambia en < 5min → override inmediato (físicamente imposible).
"""

import logging
import time
from dataclasses import dataclass, field

from app.infrastructure.cache.redis_client import redis_manager

logger = logging.getLogger(__name__)

_USER_IP_TTL = 86_400  # 24 horas


@dataclass
class IPHistoryResult:
    penalty:      int       = 0
    reason_codes: list[str] = field(default_factory=list)
    override_block: bool    = False


class IPHistoryAnalyzer:
    """
    Compara la IP actual del usuario contra la última IP registrada.
    Da penalización proporcional al tiempo entre el cambio de país.
    """

    async def check(
        self,
        user_id:    str,
        ip_address: str,
        ip_country: str,
    ) -> IPHistoryResult:
        result = IPHistoryResult()
        redis  = redis_manager.client
        key    = f"ip_history:user:{user_id}"
        now    = time.time()

        try:
            raw = await redis.get(key)

            if raw:
                raw_str = raw.decode() if isinstance(raw, bytes) else raw
                parts = raw_str.split("|")
                if len(parts) == 3:
                    prev_ip, prev_country, prev_ts_str = parts
                    prev_ts  = float(prev_ts_str)
                    elapsed  = now - prev_ts
                    minutes  = elapsed / 60

                    if prev_country != ip_country:
                        if minutes < 5:
                            # Físicamente imposible volar de país en 5 min
                            result.override_block = True
                            result.penalty        = 50
                            result.reason_codes.append("IMPOSSIBLE_IP_JUMP_5MIN")
                            logger.warning(
                                f"[IPHistory] IMPOSSIBLE JUMP user={user_id} "
                                f"{prev_country}->{ip_country} in {minutes:.1f}min"
                            )
                        elif minutes < 30:
                            result.penalty = 25
                            result.reason_codes.append("IP_COUNTRY_JUMP_30MIN")
                            logger.info(
                                f"[IPHistory] Country jump user={user_id} "
                                f"{prev_country}->{ip_country} in {minutes:.1f}min"
                            )

            # Actualizar registro con IP actual
            await redis.setex(key, _USER_IP_TTL, f"{ip_address}|{ip_country}|{now}")

        except Exception as e:
            logger.error(f"[IPHistory] Redis error: {e}")

        return result


ip_history_analyzer = IPHistoryAnalyzer()
