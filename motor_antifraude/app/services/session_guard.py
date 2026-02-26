import logging
from dataclasses import dataclass, field

from app.infrastructure.cache.redis_client import redis_manager

logger = logging.getLogger(__name__)

# TTL de 1 hora — después la sesión expira y puede reutilizarse
_SESSION_TTL = 3_600


@dataclass
class SessionGuardResult:
    penalty:        int       = 0
    reason_codes:   list[str] = field(default_factory=list)
    override_block: bool      = False


class SessionGuard:

    async def check(self, session_id: str, user_id: str) -> SessionGuardResult:
        result = SessionGuardResult()
        redis  = redis_manager.client
        key    = f"session:{session_id}"

        try:
            # SET NX es atómico — si retorna True, nadie más tenía esta sesión
            created = await redis.set(key, user_id, nx=True, ex=_SESSION_TTL)

            if created:
                return result

            # La sesión ya existía — leer quién la creó
            raw = await redis.get(key)
            owner = raw.decode() if isinstance(raw, bytes) else raw

            if owner == user_id:
                # Mismo usuario mandando el mismo session_id dos veces
                result.penalty = 40
                result.reason_codes.append("SESSION_REPLAY_ATTACK")
                logger.warning(f"[SessionGuard] Replay: user={user_id} session={session_id}")
            else:
                # session_id de otro usuario — posible robo de sesión
                result.override_block = True
                result.penalty        = 60
                result.reason_codes.append("SESSION_HIJACK_DETECTED")
                logger.error(
                    f"[SessionGuard] Hijack: session={session_id} "
                    f"owner={owner} attacker={user_id}"
                )

        except Exception as e:
            logger.error(f"[SessionGuard] Redis error: {e}")

        return result


session_guard = SessionGuard()