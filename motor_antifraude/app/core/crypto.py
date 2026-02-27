import base64
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Paths to the keys generated during deployment
BASE_DIR = Path(__file__).resolve().parent.parent
PRIVATE_KEY_PATH = BASE_DIR / "private_key.pem"
PUBLIC_KEY_PATH = BASE_DIR / "public_key.pem"

_private_key = None
_public_key_bytes = None

def _load_keys():
    global _private_key, _public_key_bytes
    if _private_key is None and PRIVATE_KEY_PATH.exists():
        with open(PRIVATE_KEY_PATH, "rb") as f:
            _private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )
    if _public_key_bytes is None and PUBLIC_KEY_PATH.exists():
        with open(PUBLIC_KEY_PATH, "r") as f:
            _public_key_bytes = f.read()

def get_public_key_pem() -> str:
    """Returns the public key as a PEM encoded string."""
    _load_keys()
    if not _public_key_bytes:
        raise RuntimeError("Public key not found on server.")
    return _public_key_bytes

def decrypt_payload(encrypted_aes_key_b64: str, iv_b64: str, ciphertext_b64: str, auth_tag_b64: str) -> dict:
    """
    1. Decrypts the AES key using the Backend's RSA Private Key.
    2. Decrypts the payload using the AES-GCM key, IV, Ciphertext, and Auth Tag.
    3. Returns the parsed JSON dictionary.
    """
    _load_keys()
    if not _private_key:
        raise RuntimeError("Private key not found on server.")

    # 1. Decode base64 inputs
    try:
        encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        auth_tag = base64.b64decode(auth_tag_b64)
    except Exception as e:
        raise ValueError(f"Invalid base64 encoding in payload: {e}")

    # 2. RSA Decrypt the AES Key
    try:
        aes_key = _private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise ValueError("Failed to decrypt AES key with RSA private key.")

    # 3. AES-GCM Decrypt the payload
    # cryptography's AESGCM expects ciphertext + tag combined
    combined_ciphertext = ciphertext + auth_tag
    
    try:
        aesgcm = AESGCM(aes_key)
        plaintext_bytes = aesgcm.decrypt(
            nonce=iv,
            data=combined_ciphertext,
            associated_data=None
        )
    except InvalidTag:
        raise ValueError("AES-GCM Authentication Failed. Data corrupted or tampered.")
    except Exception as e:
        raise ValueError(f"AES decryption failed: {e}")

    # 4. Parse JSON
    try:
        return json.loads(plaintext_bytes.decode('utf-8'))
    except json.JSONDecodeError:
        raise ValueError("Decrypted payload is not valid JSON.")
