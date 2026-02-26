import os
import hashlib
import hmac
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime, timedelta, timezone
from jose import jwt
from app.core.config import settings

class SecurityManager:
    # Se inicializa una sola vez al cargar la clase
    _key = bytes.fromhex(settings.ENCRYPTION_KEY_HEX)
    _aesgcm = AESGCM(_key)

    @classmethod
    def encrypt_data(cls, data: str) -> bytes:
        """Cifrado autenticado AES-256-GCM."""
        if not data: return b""
        nonce = os.urandom(12) 
        ciphertext = cls._aesgcm.encrypt(nonce, data.encode(), None)
        return nonce + ciphertext

    @classmethod
    def decrypt_data(cls, encrypted_bytes: bytes) -> str:
        """Descifrado de datos PII."""
        if not encrypted_bytes: return ""
        nonce = encrypted_bytes[:12]
        ciphertext = encrypted_bytes[12:]
        decrypted_data = cls._aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_data.decode()

    @classmethod
    def hash_pii(cls, data: str) -> str:
        """Hash determinista para búsquedas en DB (Email/Cédula)."""
        if not data: return ""
        salt = settings.HASH_SALT.encode()
        # Retornamos hex para que sea fácil de guardar en la DB
        return hashlib.sha256(salt + data.strip().lower().encode()).hexdigest()

    @classmethod
    def generate_hmac_signature(cls, data_dict: dict) -> str:
        """Genera firma HMAC para validar integridad de peticiones."""
        # Convertimos el diccionario a un string canónico para que el hash sea estable
        message = json.dumps(data_dict, sort_keys=True, separators=(",", ":"))
        key = settings.FRAUD_HMAC_SECRET.encode()
        return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def create_access_token(data: dict) -> str:
        """Crea el token JWT para la sesión del usuario."""
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)