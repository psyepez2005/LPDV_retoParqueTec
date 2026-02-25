"""
================================================================================
SecurityManager - Módulo de Seguridad Criptográfica
================================================================================

Este módulo implementa mecanismos criptográficos para la protección de datos
sensibles dentro de la aplicación, incluyendo:

1. Cifrado Simétrico Autenticado (AES-256-GCM)
   - Utiliza el algoritmo AES en modo GCM (Galois/Counter Mode).
   - Proporciona confidencialidad + integridad + autenticidad.
   - La clave es de 256 bits (32 bytes).
   - Se genera un nonce (IV) criptográficamente seguro de 12 bytes.
   - El output final concatena: nonce + ciphertext + authentication tag.

2. Derivación de Hash Seguro para PII
   - Aplica SHA-256 con salt estático.
   - Permite almacenar valores hash de datos sensibles (email, teléfono)
     sin guardar el dato en texto plano.
   - El uso de salt mitiga ataques de diccionario y rainbow tables.

3. Firma Digital HMAC-SHA256
   - Genera una firma basada en clave secreta.
   - Garantiza integridad y autenticidad del mensaje.
   - Utiliza construcción HMAC con SHA-256.

Configuración:
- ENCRYPTION_KEY_HEX: Clave AES-256 en formato hexadecimal (32 bytes).
- HASH_SALT: Salt utilizado para hashing de PII.
- SIGNATURE_KEY: Clave secreta para generación de firmas HMAC.

Consideraciones Criptográficas:
- AES-GCM requiere nonce único por operación.
- La clave debe almacenarse de forma segura (ej. variables de entorno).
- SHA-256 produce un digest de 256 bits.
- HMAC protege contra ataques de manipulación de mensajes.

================================================================================
"""

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