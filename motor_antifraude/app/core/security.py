import os
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.core.config import settings
class SecurityManager:
    
    _key = bytes.fromhex(settings.ENCRYPTION_KEY_HEX)
    _aesgcm = AESGCM(_key)

    @classmethod
    def encrypt_data(cls, data: str) -> bytes:
        if not data: return b""
        nonce = os.urandom(12) 
        ciphertext = cls._aesgcm.encrypt(nonce, data.encode(), None)
        return nonce + ciphertext

    @classmethod
    def decrypt_data(cls, encrypted_bytes: bytes) -> str:
        if not encrypted_bytes: return ""
        nonce = encrypted_bytes[:12]
        ciphertext = encrypted_bytes[12:]
        decrypted_data = cls._aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_data.decode()

    @classmethod
    def hash_pii(cls, data: str) -> bytes:
        if not data: return b""
        salt = settings.HASH_SALT.encode()
        return hashlib.sha256(salt + data.strip().lower().encode()).digest()

    @classmethod
    def generate_hmac_signature(cls, message: str) -> str:
        key = settings.SIGNATURE_KEY.encode()
        return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()