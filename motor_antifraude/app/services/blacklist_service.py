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
    hit: bool
    blacklist_type: Optional[BlacklistType] = None
    reason: Optional[str] = None
    added_by: Optional[str] = None  


class BlacklistService:
    

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
        
        key = f"{self.KEY_PREFIX}:{bl_type.value}:{value}"
        try:
            return await self.redis.exists(key) > 0
        except Exception as e:
            logger.error(f"[Blacklist] Error al verificar entrada: {e}")
            return False

    async def get_reason(self, bl_type: BlacklistType, value: str) -> Optional[str]:
        key = f"{self.KEY_PREFIX}:{bl_type.value}:{value}"
        try:
            raw = await self.redis.get(key)
            if raw:
                return raw.decode() if isinstance(raw, bytes) else str(raw)
        except Exception as e:
            logger.error(f"[Blacklist] Error al obtener razón: {e}")
        return None