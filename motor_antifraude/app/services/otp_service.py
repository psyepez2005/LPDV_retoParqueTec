"""
otp_service.py
--------------
Servicio de generación y validación de códigos OTP para el flujo de checkout.

Flujo completo:
  1. El usuario llena el formulario de checkout y presiona "Pagar"
  2. El backend llama generate_and_send() → genera OTP, lo guarda en
     Redis con TTL 5 min, y lo envía al email del usuario
  3. El usuario ingresa el código en el frontend
  4. El backend llama verify() → valida el código y retorna True/False
  5. Si es válido → se llama al motor antifraude para evaluar la tx
  6. Si es inválido → se incrementa el contador de intentos fallidos
     Al tercer intento fallido el OTP se cancela automáticamente

Estructura de keys en Redis:
  otp:{user_id}:code      → código OTP hasheado (TTL 5 min)
  otp:{user_id}:attempts  → contador de intentos fallidos (TTL 5 min)
  otp:{user_id}:context   → datos de la transacción pendiente (TTL 5 min)

Seguridad:
  - El OTP se guarda hasheado con SHA-256 en Redis (nunca en texto plano)
  - Máximo 3 intentos fallidos antes de cancelar el OTP
  - TTL de 5 minutos: el código expira automáticamente
  - Rate limiting: no se puede generar un OTP nuevo si ya hay uno activo
    y han pasado menos de 60 segundos desde el último
"""

import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Optional
import json

from app.core.exceptions import (
    OtpExpiredException,
    OtpInvalidException,
    OtpMaxAttemptsException,
    OtpAlreadyUsedException,
)
from app.infrastructure.cache.redis_client import redis_manager
from app.infrastructure.messaging.email_service import email_service

logger = logging.getLogger(__name__)

OTP_TTL_SECONDS      = 60 * 5    
OTP_MAX_ATTEMPTS     = 3         
OTP_COOLDOWN_SECONDS = 60        
OTP_LENGTH           = 6         


class OtpService:
    
    CODE_KEY     = "otp:{user_id}:code"
    ATTEMPTS_KEY = "otp:{user_id}:attempts"
    CONTEXT_KEY  = "otp:{user_id}:context"
    COOLDOWN_KEY = "otp:{user_id}:cooldown"

   
    async def generate_and_send(
        self,
        user_id: str,
        email: str,
        transaction_context: dict,
    ) -> bool:
    
        redis = redis_manager.client

        cooldown_key = self.COOLDOWN_KEY.format(user_id=user_id)
        if await redis.exists(cooldown_key):
            ttl = await redis.ttl(cooldown_key)
            logger.warning(
                f"[OTP] Solicitud en cooldown para user={user_id} "
                f"— esperar {ttl}s"
            )
            return True

        otp_code = str(secrets.randbelow(10 ** OTP_LENGTH)).zfill(OTP_LENGTH)

        otp_hash = self._hash_otp(otp_code)

        try:
            pipe = redis.pipeline()

            pipe.setex(
                self.CODE_KEY.format(user_id=user_id),
                OTP_TTL_SECONDS,
                otp_hash,
            )

            pipe.setex(
                self.ATTEMPTS_KEY.format(user_id=user_id),
                OTP_TTL_SECONDS,
                "0",
            )

            pipe.setex(
                self.CONTEXT_KEY.format(user_id=user_id),
                OTP_TTL_SECONDS,
                json.dumps(transaction_context),
            )

            pipe.setex(cooldown_key, OTP_COOLDOWN_SECONDS, "1")

            await pipe.execute()

        except Exception as e:
            logger.error(f"[OTP] Error guardando OTP en Redis para user={user_id}: {e}")
            return False

        sent = await email_service.send_otp(to=email, otp_code=otp_code)

        if sent:
            logger.info(f"[OTP] Generado y enviado para user={user_id} → {email}")
        else:
            logger.error(f"[OTP] Error enviando email a {email} para user={user_id}")

        return sent

    async def verify(self, user_id: str, otp_input: str) -> dict:
        
        redis = redis_manager.client

        code_key     = self.CODE_KEY.format(user_id=user_id)
        attempts_key = self.ATTEMPTS_KEY.format(user_id=user_id)
        context_key  = self.CONTEXT_KEY.format(user_id=user_id)

        stored_hash = await redis.get(code_key)
        if not stored_hash:
            logger.warning(f"[OTP] OTP expirado o no existe para user={user_id}")
            raise OtpExpiredException()

        raw_attempts = await redis.get(attempts_key)
        attempts = int(raw_attempts) if raw_attempts else 0

        if attempts >= OTP_MAX_ATTEMPTS:
            await self._invalidate(user_id)
            logger.warning(
                f"[OTP] Máximo de intentos alcanzado para user={user_id}"
            )
            raise OtpMaxAttemptsException()

        input_hash = self._hash_otp(otp_input.strip())
        stored_hash_str = (
            stored_hash.decode() if isinstance(stored_hash, bytes)
            else stored_hash
        )

        if input_hash != stored_hash_str:
            await redis.incr(attempts_key)
            remaining = OTP_MAX_ATTEMPTS - (attempts + 1)
            logger.warning(
                f"[OTP] Código incorrecto para user={user_id} "
                f"— intentos restantes: {remaining}"
            )
            raise OtpInvalidException(
                f"Código incorrecto. Te quedan {remaining} intento(s)."
            )

        raw_context = await redis.get(context_key)
        context = json.loads(raw_context) if raw_context else {}

        await self._invalidate(user_id)

        logger.info(f"[OTP] Verificado correctamente para user={user_id}")
        return context


    async def _invalidate(self, user_id: str) -> None:
        """Elimina todos los keys del OTP de Redis."""
        redis = redis_manager.client
        try:
            await redis.delete(
                self.CODE_KEY.format(user_id=user_id),
                self.ATTEMPTS_KEY.format(user_id=user_id),
                self.CONTEXT_KEY.format(user_id=user_id),
            )
        except Exception as e:
            logger.error(f"[OTP] Error invalidando OTP para user={user_id}: {e}")

    def _hash_otp(self, otp: str) -> str:
        
        return hashlib.sha256(otp.encode()).hexdigest()

    async def has_active_otp(self, user_id: str) -> bool:
        key = self.CODE_KEY.format(user_id=user_id)
        try:
            return await redis_manager.client.exists(key) > 0
        except Exception:
            return False

    async def get_remaining_attempts(self, user_id: str) -> int:
        key = self.ATTEMPTS_KEY.format(user_id=user_id)
        try:
            raw = await redis_manager.client.get(key)
            used = int(raw) if raw else 0
            return max(0, OTP_MAX_ATTEMPTS - used)
        except Exception:
            return OTP_MAX_ATTEMPTS


otp_service = OtpService()