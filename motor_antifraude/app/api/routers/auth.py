

from typing import Optional
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
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.security import SecurityManager 


router = APIRouter(prefix="/v1/auth", tags=["Autenticación"])

MAX_PHOTO_SIZE_BYTES = 5 * 1024 * 1024

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
    email:      str                  = Form(..., description="Correo electrónico"),
    username:   str                  = Form(..., min_length=3, max_length=50),
    password:   str                  = Form(..., min_length=8),
    cedula:     str                  = Form(..., min_length=6, max_length=20),
    face_photo: Optional[UploadFile] = File(None, description="Foto frontal del rostro (JPG/PNG) — opcional"),
    db: AsyncSession                 = Depends(get_db_session),
):


    face_bytes: Optional[bytes] = None
    if face_photo is not None:
        if face_photo.content_type not in ALLOWED_CONTENT_TYPES:
            raise HTTPException(
                status_code = status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail      = "Formato de imagen no soportado. Usa JPG, PNG o WebP.",
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

    if not cedula.isdigit():
        raise HTTPException(
            status_code = status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail      = "La cédula solo debe contener números.",
        )

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


@router.post("/login")
async def login(
    payload: UserLoginRequest,
    db: AsyncSession = Depends(get_db_session),
):
    try:
        # 1. El servicio valida email_hash y password
        user = await auth_service.login(
            db       = db,
            email    = payload.email,
            password = payload.password,
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Credenciales inválidas"
            )

        # 2. Generamos el Token JWT (La "llave" de acceso)
        # El 'sub' (subject) del token será el ID único del usuario
        access_token = SecurityManager.create_access_token(
            data={"sub": str(user.id)}
        )

        # 3. Retornamos el token al frontend/wallet
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "message": "Bienvenido a Plux",
            "user_id": str(user.id)
        }

    except FraudMotorException as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)