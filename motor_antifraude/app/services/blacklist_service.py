"""
blacklist_service.py
--------------------
Primera línea de defensa del Motor Antifraude.

Verifica user_id, device_id, ip_address y card_bin contra listas negras
almacenadas en Redis ANTES de calcular cualquier score. Si hay un hit,
el orquestador responde ACTION_BLOCK_PERM en < 3ms sin ejecutar ningún
otro módulo de análisis.

Principio de diseño:
  - Un solo mget en Redis cubre todas las entidades (O(N) sobre pocos keys)
  - Los bloqueos pueden ser permanentes o temporales (con TTL)
  - Cada entrada registra la razón del bloqueo para auditoría
  - El analista puede remover entradas vía remove() cuando se confirma
    falso positivo, evitando bloqueos injustos permanentes
"""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from redis.asyncio import Redis

logger = logging.getLogger(__name__)


class BlacklistType(str, Enum):
    USER   = "user"
    DEVICE = "device"
    IP     = "ip"
    BIN    = "bin"
    EMAIL  = "email"
    PHONE  = "phone"


@dataclass
class BlacklistHit:
    """
    Resultado de la verificación.
    hit=False significa que ninguna entidad está bloqueada.
    hit=True significa bloqueo inmediato con la razón registrada.
    """
    hit: bool
    blacklist_type: Optional[BlacklistType] = None
    reason: Optional[str] = None
    added_by: Optional[str] = None   # "system" | "analyst"


class BlacklistService:
    """
    Consulta y gestiona todas las listas negras internas del motor.

    Estructura de keys en Redis:
      blacklist:user:{user_id}      → razón del bloqueo (string)
      blacklist:device:{device_id}  → razón del bloqueo (string)
      blacklist:ip:{ip_address}     → razón del bloqueo (string)
      blacklist:bin:{card_bin}      → razón del bloqueo (string)
      blacklist:email:{email}       → razón del bloqueo (string)
      blacklist:phone:{phone}       → razón del bloqueo (string)

    Ejemplo de uso en el orquestador (ANTES del asyncio.gather):

        bl = await self.blacklist.check(
            user_id=str(payload.user_id),
            device_id=payload.device_id,
            ip_address=payload.ip_address,
            card_bin=payload.card_bin,
        )
        if bl.hit:
            return BLOCK_PERM_inmediato

    Ejemplo de uso desde el panel de analistas:

        # Bloquear un usuario de forma permanente
        await bl_service.add(BlacklistType.USER, user_id, reason="fraude_confirmado")

        # Bloquear una IP temporalmente por 24 horas
        await bl_service.add(BlacklistType.IP, ip, reason="brute_force", temporary=True)

        # Revertir un falso positivo
        await bl_service.remove(BlacklistType.USER, user_id)
    """

    KEY_PREFIX = "blacklist"

    TEMP_BLOCK_TTL = 60 * 60 * 24

    def __init__(self, redis_client: Redis):
        self.redis = redis_client

    async def check(
        self,
        user_id: str,
        device_id: str,
        ip_address: str,
        card_bin: str,
        email: Optional[str] = None,
        phone: Optional[str] = None,
    ) -> BlacklistHit:
        """
        Verifica todas las entidades en UNA SOLA llamada mget a Redis.
        Tiempo esperado: 1-3ms.

        Si Redis no responde, retorna BlacklistHit(hit=False) para no
        bloquear transacciones legítimas por un fallo de infraestructura.
        """
        keys = {
            BlacklistType.USER:   f"{self.KEY_PREFIX}:{BlacklistType.USER}:{user_id}",
            BlacklistType.DEVICE: f"{self.KEY_PREFIX}:{BlacklistType.DEVICE}:{device_id}",
            BlacklistType.IP:     f"{self.KEY_PREFIX}:{BlacklistType.IP}:{ip_address}",
            BlacklistType.BIN:    f"{self.KEY_PREFIX}:{BlacklistType.BIN}:{card_bin}",
        }

        if email:
            keys[BlacklistType.EMAIL] = (
                f"{self.KEY_PREFIX}:{BlacklistType.EMAIL}:{email}"
            )
        if phone:
            keys[BlacklistType.PHONE] = (
                f"{self.KEY_PREFIX}:{BlacklistType.PHONE}:{phone}"
            )

        key_list  = list(keys.values())
        type_list = list(keys.keys())

        try:
            results = await self.redis.mget(*key_list)
        except Exception as e:
            logger.error(f"[Blacklist] Redis error durante mget: {e}")
            return BlacklistHit(hit=False)

        for bl_type, value in zip(type_list, results):
            if value is not None:
                reason_str = (
                    value.decode() if isinstance(value, bytes) else str(value)
                )
                logger.warning(
                    f"[Blacklist] HIT — "
                    f"type={bl_type.value}  reason={reason_str}"
                )
                return BlacklistHit(
                    hit=True,
                    blacklist_type=bl_type,
                    reason=reason_str,
                    added_by="system",
                )

        return BlacklistHit(hit=False)

    async def add(
        self,
        bl_type: BlacklistType,
        value: str,
        reason: str,
        temporary: bool = False,
        ttl_seconds: int = TEMP_BLOCK_TTL,
    ) -> bool:
        """
        Agrega una entidad a la blacklist.

        temporary=True  → bloqueo con TTL (se borra automáticamente)
        temporary=False → bloqueo permanente hasta que un analista lo revierte

        Retorna True si se guardó correctamente, False si hubo error.
        """
        key = f"{self.KEY_PREFIX}:{bl_type.value}:{value}"
        try:
            if temporary:
                await self.redis.setex(key, ttl_seconds, reason)
            else:
                await self.redis.set(key, reason)

            logger.info(
                f"[Blacklist] Entrada agregada — "
                f"type={bl_type.value}  value={value}  reason={reason}  "
                f"temporary={temporary}"
            )
            return True

        except Exception as e:
            logger.error(f"[Blacklist] Error al agregar entrada: {e}")
            return False

    async def remove(self, bl_type: BlacklistType, value: str) -> bool:
        """
        Elimina una entidad de la blacklist.
        Usar cuando el equipo de riesgo confirma un falso positivo.

        Retorna True si se eliminó, False si no existía o hubo error.
        """
        key = f"{self.KEY_PREFIX}:{bl_type.value}:{value}"
        try:
            deleted = await self.redis.delete(key)
            if deleted:
                logger.info(
                    f"[Blacklist] Entrada eliminada (falso positivo revertido) — "
                    f"type={bl_type.value}  value={value}"
                )
            return deleted > 0

        except Exception as e:
            logger.error(f"[Blacklist] Error al eliminar entrada: {e}")
            return False

    async def is_blocked(self, bl_type: BlacklistType, value: str) -> bool:
        """
        Verifica si una entidad específica está bloqueada.
        Útil para validaciones puntuales fuera del flujo principal.
        """
        key = f"{self.KEY_PREFIX}:{bl_type.value}:{value}"
        try:
            return await self.redis.exists(key) > 0
        except Exception as e:
            logger.error(f"[Blacklist] Error al verificar entrada: {e}")
            return False

    async def get_reason(self, bl_type: BlacklistType, value: str) -> Optional[str]:
        """Retorna la razón del bloqueo o None si no está bloqueado."""
        key = f"{self.KEY_PREFIX}:{bl_type.value}:{value}"
        try:
            raw = await self.redis.get(key)
            if raw:
                return raw.decode() if isinstance(raw, bytes) else str(raw)
        except Exception as e:
            logger.error(f"[Blacklist] Error al obtener razón: {e}")
        return None