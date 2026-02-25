"""
dependencies.py
---------------
Dependencias reutilizables para inyectar en los routers de FastAPI.

get_db_session:
  Sesión de base de datos — tu implementación original.

get_current_user:
  Lee el JWT del header Authorization, lo valida y retorna el usuario.
  Usar con Depends() en cualquier endpoint que requiera autenticación:

      @router.get("/perfil")
      async def perfil(user: CurrentUser = Depends(get_current_user)):
          return {"username": user.username}
"""

from typing import AsyncGenerator

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database.session import AsyncSessionLocal
from app.core.exceptions import InvalidTokenException
from app.domain.schemas import CurrentUser
from app.services.auth_service import auth_service

# ── Sesión de base de datos ───────────────────────────────────────────

async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    session = AsyncSessionLocal()
    try:
        yield session
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


# ── Autenticación JWT ─────────────────────────────────────────────────

# Esquema Bearer para que Swagger muestre el candado en los endpoints
bearer_scheme = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> CurrentUser:
    """
    Extrae y valida el JWT del header Authorization.

    Lanza HTTP 401 si el token es inválido o expiró.
    """
    try:
        return auth_service.verify_token(credentials.credentials)
    except InvalidTokenException as e:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail      = e.message,
            headers     = {"WWW-Authenticate": "Bearer"},
        )