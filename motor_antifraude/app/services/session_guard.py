"""
session_guard.py
----------------
Protección contra replay attacks y session hijacking.

Usa SET NX (set if not exists) de Redis para garantizar que
cada session_id sea usado exactamente una vez.

- Replay attack: el mismo session_id enviado dos veces → +40 pts
- Session hijacking: el session_id fue emitido para otro user_id → BLOCK_PERM
"""

import logging
from dataclasses import dataclass, field

from app.infrastructure.cache.redis_client import redis_manager

logger = logging.getLogger(__name__)

_SESSION_TTL = 3_600  # 1 hora — después de eso la sesión expira normalmente


@dataclass
class SessionGuardResult:
    penalty:        int       = 0
    reason_codes:   list[str] = field(default_factory=list)
    override_block: bool      = False


class SessionGuard:
    """
    Garantiza unicidad de session_id por usuario.
    Operación atómica con SET NX — thread-safe por diseño de Redis.
    """

    async def check(
        self,
        session_id: str,
        user_id:    str,
    ) -> SessionGuardResult:
        result = SessionGuardResult()
        redis  = redis_manager.client
        key    = f"session:{session_id}"

        try:
            # SET key value NX EX ttl → retorna True si se creó, None si ya existía
            created = await redis.set(key, user_id, nx=True, ex=_SESSION_TTL)

            if created:
                # Primera vez que se ve esta sesión → OK
                return result

            # La sesión ya existe — checar si es del mismo usuario
            existing_user = await redis.get(key)

            if existing_user == user_id:
                # Mismo usuario reutilizando session_id → replay attack
                result.penalty = 40
                result.reason_codes.append("SESSION_REPLAY_ATTACK")
                logger.warning(
                    f"[SessionGuard] REPLAY user={user_id} session={session_id}"
                )
            else:
                # Otro usuario intentó usar una sesión ajena → session hijacking
                result.override_block = True
                result.penalty        = 60
                result.reason_codes.append("SESSION_HIJACK_DETECTED")
                logger.error(
                    f"[SessionGuard] HIJACK session={session_id} "
                    f"owner={existing_user} attacker={user_id}"
                )

        except Exception as e:
            logger.error(f"[SessionGuard] Redis error: {e}")

        return result


session_guard = SessionGuard()
