from fastapi import Depends, HTTPException, Header, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from app.core.config import settings
from app.services.fraud_orchestrator import fraud_orchestrator

# Configuración para que Swagger sepa dónde pedir el token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="v1/auth/login")

# ── 1. CERRADURA DE IDENTIDAD: JWT ───────────────────────────────────
async def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Verifica que el token sea válido y no haya expirado.
    """
    try:
        # Usamos la SECRET_KEY y ALGORITHM de tu .env
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="El token no contiene identificación de usuario"
            )
        return user_id
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Token inválido, manipulado o expirado"
        )

# # ── 2. CERRADURA DE INTEGRIDAD: HMAC ─────────────────────────────────
# async def validate_hmac_integrity(request: Request, x_signature: str = Header(...)):
#     """
#     Verifica que el JSON de la transacción coincida con la firma enviada.
#     Evita que alguien cambie el 'amount' durante el envío.
#     """
#     # Obtenemos el cuerpo de la petición tal cual llegó
#     body = await request.json()
    
#     # Usamos la función que añadimos al orquestador en el paso anterior
#     if not fraud_orchestrator.verify_incoming_hmac(body, x_signature):
#         raise HTTPException(
#             status_code=status.HTTP_403_FORBIDDEN, 
#             detail="Firma de seguridad inválida: La petición fue manipulada"
#         )
#     return body