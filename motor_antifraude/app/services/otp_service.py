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

# ── Configuración ─────────────────────────────────────────────────────
OTP_TTL_SECONDS      = 60 * 5    # 5 minutos de validez
OTP_MAX_ATTEMPTS     = 3         # Máximo intentos fallidos
OTP_COOLDOWN_SECONDS = 60        # Esperar 60s antes de pedir otro OTP
OTP_LENGTH           = 6         # Dígitos del código


class OtpService:
    """
    Gestiona el ciclo de vida completo de un OTP:
    generación → envío → validación → invalidación.
    """

    # Keys de Redis
    CODE_KEY     = "otp:{user_id}:code"
    ATTEMPTS_KEY = "otp:{user_id}:attempts"
    CONTEXT_KEY  = "otp:{user_id}:context"
    COOLDOWN_KEY = "otp:{user_id}:cooldown"

    # ------------------------------------------------------------------ #
    #  Generación y envío                                                #
    # ------------------------------------------------------------------ #

    async def generate_and_send(
        self,
        user_id: str,
        email: str,
        transaction_context: dict,
    ) -> bool:
        """
        Genera un OTP de 6 dígitos, lo guarda en Redis y lo envía por email.

        Parámetros:
          user_id             → ID del usuario que inicia el checkout
          email               → correo donde se envía el OTP
          transaction_context → datos de la tx pendiente (amount, currency, etc.)
                                se guardan en Redis para recuperarlos al validar

        Retorna True si el email se envió correctamente.

        Lanza nada — si algo falla retorna False para que el router
        maneje el error sin exponer detalles internos al usuario.
        """
        redis = redis_manager.client

        # ── Cooldown: evitar spam de OTPs ─────────────────────────────
        cooldown_key = self.COOLDOWN_KEY.format(user_id=user_id)
        if await redis.exists(cooldown_key):
            ttl = await redis.ttl(cooldown_key)
            logger.warning(
                f"[OTP] Solicitud en cooldown para user={user_id} "
                f"— esperar {ttl}s"
            )
            # Retornamos True para no revelar que ya hay un OTP activo
            # El usuario simplemente debe esperar y revisar su correo
            return True

        # ── Generar código aleatorio seguro ───────────────────────────
        # secrets.randbelow es criptográficamente seguro (no usar random)
        otp_code = str(secrets.randbelow(10 ** OTP_LENGTH)).zfill(OTP_LENGTH)

        # ── Hashear antes de guardar en Redis ─────────────────────────
        # Nunca guardar el OTP en texto plano — si Redis es comprometido
        # el atacante no puede usar los códigos directamente
        otp_hash = self._hash_otp(otp_code)

        try:
            pipe = redis.pipeline()

            # Guardar hash del OTP con TTL de 5 minutos
            pipe.setex(
                self.CODE_KEY.format(user_id=user_id),
                OTP_TTL_SECONDS,
                otp_hash,
            )

            # Resetear contador de intentos
            pipe.setex(
                self.ATTEMPTS_KEY.format(user_id=user_id),
                OTP_TTL_SECONDS,
                "0",
            )

            # Guardar contexto de la transacción pendiente
            pipe.setex(
                self.CONTEXT_KEY.format(user_id=user_id),
                OTP_TTL_SECONDS,
                json.dumps(transaction_context),
            )

            # Cooldown de 60s para no generar OTPs en cadena
            pipe.setex(cooldown_key, OTP_COOLDOWN_SECONDS, "1")

            await pipe.execute()

        except Exception as e:
            logger.error(f"[OTP] Error guardando OTP en Redis para user={user_id}: {e}")
            return False

        # ── Enviar por email ──────────────────────────────────────────
        sent = await email_service.send_otp(to=email, otp_code=otp_code)

        if sent:
            logger.info(f"[OTP] Generado y enviado para user={user_id} → {email}")
        else:
            logger.error(f"[OTP] Error enviando email a {email} para user={user_id}")

        return sent

    # ------------------------------------------------------------------ #
    #  Validación                                                        #
    # ------------------------------------------------------------------ #

    async def verify(self, user_id: str, otp_input: str) -> dict:
        """
        Valida el OTP ingresado por el usuario.

        Retorna el contexto de la transacción pendiente si el OTP es válido.
        Lanza excepción si el OTP es inválido, expirado o ya fue usado.

        Parámetros:
          user_id   → ID del usuario
          otp_input → código de 6 dígitos ingresado por el usuario

        Retorna:
          dict con el contexto de la transacción guardado al generar el OTP

        Lanza:
          OtpExpiredException    → el OTP ya no existe en Redis (expiró)
          OtpMaxAttemptsException → superó los 3 intentos fallidos
          OtpInvalidException    → el código es incorrecto
        """
        redis = redis_manager.client

        code_key     = self.CODE_KEY.format(user_id=user_id)
        attempts_key = self.ATTEMPTS_KEY.format(user_id=user_id)
        context_key  = self.CONTEXT_KEY.format(user_id=user_id)

        # ── Verificar que el OTP existe (no expiró) ───────────────────
        stored_hash = await redis.get(code_key)
        if not stored_hash:
            logger.warning(f"[OTP] OTP expirado o no existe para user={user_id}")
            raise OtpExpiredException()

        # ── Verificar intentos fallidos ───────────────────────────────
        raw_attempts = await redis.get(attempts_key)
        attempts = int(raw_attempts) if raw_attempts else 0

        if attempts >= OTP_MAX_ATTEMPTS:
            # Limpiar el OTP para forzar que soliciten uno nuevo
            await self._invalidate(user_id)
            logger.warning(
                f"[OTP] Máximo de intentos alcanzado para user={user_id}"
            )
            raise OtpMaxAttemptsException()

        # ── Comparar hash del input con el hash guardado ──────────────
        input_hash = self._hash_otp(otp_input.strip())
        stored_hash_str = (
            stored_hash.decode() if isinstance(stored_hash, bytes)
            else stored_hash
        )

        if input_hash != stored_hash_str:
            # Incrementar contador de intentos fallidos
            await redis.incr(attempts_key)
            remaining = OTP_MAX_ATTEMPTS - (attempts + 1)
            logger.warning(
                f"[OTP] Código incorrecto para user={user_id} "
                f"— intentos restantes: {remaining}"
            )
            raise OtpInvalidException(
                f"Código incorrecto. Te quedan {remaining} intento(s)."
            )

        # ── OTP válido → obtener contexto y limpiar ───────────────────
        raw_context = await redis.get(context_key)
        context = json.loads(raw_context) if raw_context else {}

        # Invalidar el OTP inmediatamente — no puede reutilizarse
        await self._invalidate(user_id)

        logger.info(f"[OTP] Verificado correctamente para user={user_id}")
        return context

    # ------------------------------------------------------------------ #
    #  Utilidades                                                        #
    # ------------------------------------------------------------------ #

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
        """
        Hashea el OTP con SHA-256.
        Simple y rápido — no necesitamos bcrypt aquí porque
        los OTPs ya son cortos, aleatorios y de vida muy corta.
        """
        return hashlib.sha256(otp.encode()).hexdigest()

    async def has_active_otp(self, user_id: str) -> bool:
        """Verifica si el usuario tiene un OTP activo en Redis."""
        key = self.CODE_KEY.format(user_id=user_id)
        try:
            return await redis_manager.client.exists(key) > 0
        except Exception:
            return False

    async def get_remaining_attempts(self, user_id: str) -> int:
        """Retorna los intentos restantes para el OTP activo."""
        key = self.ATTEMPTS_KEY.format(user_id=user_id)
        try:
            raw = await redis_manager.client.get(key)
            used = int(raw) if raw else 0
            return max(0, OTP_MAX_ATTEMPTS - used)
        except Exception:
            return OTP_MAX_ATTEMPTS


# Singleton
otp_service = OtpService()