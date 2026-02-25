"""
auth.py
-------
Router de autenticación — registro y login.

Endpoints:
  POST /v1/auth/register → registro con foto de cara (multipart/form-data)
  POST /v1/auth/login    → login con email y contraseña (JSON)
"""

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import FraudMotorException
from app.domain.schemas import (
    UserLoginRequest,
    UserLoginResponse,
    UserRegisterResponse,
)
from app.api.dependencies import get_db_session
from app.services.auth_service import auth_service

router = APIRouter(prefix="/v1/auth", tags=["Autenticación"])

# Tamaño máximo de foto: 5MB
MAX_PHOTO_SIZE_BYTES = 5 * 1024 * 1024

# Tipos de imagen permitidos
ALLOWED_CONTENT_TYPES = {"image/jpeg", "image/png", "image/webp"}


@router.post(
    "/register",
    response_model = UserRegisterResponse,
    status_code    = status.HTTP_201_CREATED,
    summary        = "Registrar nuevo usuario",
    description    = (
        "Registra un usuario nuevo con foto de cara para verificación biométrica. "
        "Enviar como multipart/form-data."
    ),
)
async def register(
    email:      str        = Form(..., description="Correo electrónico"),
    username:   str        = Form(..., min_length=3, max_length=50),
    password:   str        = Form(..., min_length=8),
    cedula:     str        = Form(..., min_length=6, max_length=20),
    face_photo: UploadFile = File(..., description="Foto frontal del rostro (JPG/PNG)"),
    db: AsyncSession       = Depends(get_db_session),
):
    """
    Registra un nuevo usuario.

    Recibe los datos como multipart/form-data porque incluye una foto.
    La foto debe ser:
      - Formato JPG, PNG o WebP
      - Máximo 5MB
      - Con un rostro frontal claramente visible
      - Buena iluminación, sin lentes de sol
    """

    # ── Validar foto ──────────────────────────────────────────────────
    if face_photo.content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(
            status_code = status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail      = f"Formato de imagen no soportado. Usa JPG, PNG o WebP.",
        )

    face_bytes = await face_photo.read()

    if len(face_bytes) > MAX_PHOTO_SIZE_BYTES:
        raise HTTPException(
            status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail      = "La foto no puede superar los 5MB.",
        )

    if len(face_bytes) == 0:
        raise HTTPException(
            status_code = status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail      = "La foto está vacía.",
        )

    # ── Validar campos del form manualmente ───────────────────────────
    # (Form no usa los validators de Pydantic automáticamente)
    if not cedula.isdigit():
        raise HTTPException(
            status_code = status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail      = "La cédula solo debe contener números.",
        )

    # ── Delegar al servicio ───────────────────────────────────────────
    try:
        return await auth_service.register(
            db               = db,
            email            = email,
            username         = username,
            password         = password,
            cedula           = cedula,
            face_image_bytes = face_bytes,
        )
    except FraudMotorException as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post(
    "/login",
    response_model = UserLoginResponse,
    summary        = "Iniciar sesión",
)
async def login(
    payload: UserLoginRequest,
    db: AsyncSession = Depends(get_db_session),
):
    """
    Autentica al usuario y retorna un JWT válido por 24 horas.

    El token debe incluirse en el header de las siguientes peticiones:
        Authorization: Bearer <token>
    """
    try:
        return await auth_service.login(
            db       = db,
            email    = payload.email,
            password = payload.password,
        )
    except FraudMotorException as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)