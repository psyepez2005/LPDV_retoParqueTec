"""
SERVICIO DE AUTENTICACIÓN (AuthService)
---------------------------------------
Este módulo centraliza la seguridad de la aplicación:
1. Registro: Valida duplicados, hashea contraseñas y procesa biometría facial.
2. Login: Verifica credenciales y genera tokens JWT de acceso.
3. Validación: Verifica la autenticidad y expiración de los tokens en cada petición.
4. Privacidad: Anonimiza datos sensibles (Cédula) mediante hashing.
"""

import hashlib
from typing import Optional
import logging
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import (
    FraudMotorException,
    InvalidTokenException,
    EmailAlreadyExistsException,
    UsernameAlreadyExistsException,
    CedulaAlreadyExistsException,
    InvalidCredentialsException,
    AccountSuspendedException,
    FaceNotDetectedException,
)
from app.domain.models import User
from app.domain.schemas import (
    UserRegisterResponse,
    UserLoginResponse,
    CurrentUser,
)

logger = logging.getLogger(__name__)

JWT_ALGORITHM    = "HS256"
JWT_EXPIRE_HOURS = 24


class AuthService:

    async def register(
        self,
        db: AsyncSession,
        email: str,
        username: str,
        password: str,
        cedula: str,
        face_image_bytes: Optional[bytes] = None,
    ) -> UserRegisterResponse:

        await self._check_email_available(db, email)
        await self._check_username_available(db, username)
        await self._check_cedula_available(db, cedula)

        hashed_password = bcrypt.hashpw(
            password.encode(),
            bcrypt.gensalt(rounds=12),
        ).decode()

        cedula_hash  = self._hash_cedula(cedula)
        cedula_last4 = cedula[-4:]

        face_image_encrypted    = None
        face_encoding_encrypted = None
        if face_image_bytes:
            try:
                from app.services.face_service import face_service
                face_image_encrypted, face_encoding_encrypted = (
                    await face_service.process_registration_photo(face_image_bytes)
                )
            except FaceNotDetectedException:
                raise
            except Exception as e:
                logger.error(f"[Auth] Error procesando foto de cara: {e}")
                raise FaceNotDetectedException()

        user = User(
            id                      = uuid.uuid4(),
            email                   = email.lower(),
            username                = username.lower(),
            hashed_password         = hashed_password,
            cedula_hash             = cedula_hash,
            cedula_last4            = cedula_last4,
            face_image_encrypted    = face_image_encrypted,
            face_encoding_encrypted = face_encoding_encrypted,
            kyc_level               = "basic",
            mfa_active              = False,
            is_active               = True,
            is_suspended            = False,
        )

        db.add(user)
        await db.commit()

        logger.info(f"[Auth] Usuario registrado: {email} (id={user.id})")

        return UserRegisterResponse(
            user_id  = user.id,
            email    = user.email,
            username = user.username,
            message  = "Cuenta creada exitosamente.",
        )

    
    async def login(
        self,
        db: AsyncSession,
        email: str,
        password: str,
    ) -> UserLoginResponse:

        result = await db.execute(
            select(User).where(User.email == email.lower())
        )
        user = result.scalar_one_or_none()

        if not user:
            raise InvalidCredentialsException()

        password_valid = bcrypt.checkpw(
            password.encode(),
            user.hashed_password.encode(),
        )
        if not password_valid:
            raise InvalidCredentialsException()

        if user.is_suspended:
            raise AccountSuspendedException()

        if not user.is_active:
            raise InvalidCredentialsException()

        user.last_login_at = datetime.now(timezone.utc)

        token, expires_in = self._generate_jwt(user)

        logger.info(f"[Auth] Login exitoso: {email} (id={user.id})")

        return UserLoginResponse(
            access_token = token,
            token_type   = "bearer",
            expires_in   = expires_in,
            user_id      = user.id,
            username     = user.username,
        )

   
    def verify_token(self, token: str) -> CurrentUser:
        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[JWT_ALGORITHM],
            )
            return CurrentUser(
                user_id   = payload["sub"],
                email     = payload["email"],
                username  = payload["username"],
                kyc_level = payload.get("kyc_level", "none"),
            )
        except jwt.ExpiredSignatureError:
            raise InvalidTokenException("Token expirado. Inicia sesión nuevamente.")
        except jwt.InvalidTokenError:
            raise InvalidTokenException()

 
    def _generate_jwt(self, user: User) -> tuple[str, int]:
        expires_in = JWT_EXPIRE_HOURS * 3600
        expire     = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS)

        payload = {
            "sub":       str(user.id),
            "email":     user.email,
            "username":  user.username,
            "kyc_level": user.kyc_level,
            "exp":       expire,
            "iat":       datetime.now(timezone.utc),
        }

        token = jwt.encode(payload, settings.SECRET_KEY, algorithm=JWT_ALGORITHM)
        return token, expires_in

    def _hash_cedula(self, cedula: str) -> bytes:
        salted = f"{settings.SECRET_KEY}:{cedula}"
        return hashlib.sha256(salted.encode()).digest()

    async def _check_email_available(self, db: AsyncSession, email: str) -> None:
        result = await db.execute(
            select(User).where(User.email == email.lower())
        )
        if result.scalar_one_or_none():
            raise EmailAlreadyExistsException()

    async def _check_username_available(self, db: AsyncSession, username: str) -> None:
        result = await db.execute(
            select(User).where(User.username == username.lower())
        )
        if result.scalar_one_or_none():
            raise UsernameAlreadyExistsException()

    async def _check_cedula_available(self, db: AsyncSession, cedula: str) -> None:
        cedula_hash = self._hash_cedula(cedula)
        result = await db.execute(
            select(User).where(User.cedula_hash == cedula_hash)
        )
        if result.scalar_one_or_none():
            raise CedulaAlreadyExistsException()



auth_service = AuthService()