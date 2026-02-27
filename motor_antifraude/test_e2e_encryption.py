import os
import json
import base64
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from datetime import datetime, timezone
import uuid

API_BASE_URL = "http://localhost:8000/v1"
session = requests.Session()

def register_and_login():
    email = f"test_{uuid.uuid4().hex[:8]}@example.com"
    password = "Password123"
    
    print("\n[Auth] Registering dummy user...")
    reg_data = {
        "email": email,
        "username": f"user_{uuid.uuid4().hex[:5]}",
        "password": password,
        "cedula": str(uuid.uuid4().int)[:10]
    }
    
    reg_resp = session.post(f"{API_BASE_URL}/auth/register", data=reg_data)
    if reg_resp.status_code != 201:
        print(f"[Auth] Register failed: {reg_resp.text}")
        return None
        
    print("[Auth] Logging in...")
    login_data = {
        "email": email,
        "password": password
    }
    login_resp = session.post(f"{API_BASE_URL}/auth/login", json=login_data)
    
    if login_resp.status_code == 200:
        token = login_resp.json()["access_token"]
        user_id = login_resp.json()["user_id"]
        session.headers.update({"Authorization": f"Bearer {token}"})
        return user_id
    else:
        print(f"[Auth] Login failed: {login_resp.text}")
        return None

def test_encryption_flow():
    user_id = register_and_login()
    if not user_id:
        return

    print("\n1. Fetching Public Key from backend...")
    response = session.get(f"{API_BASE_URL}/transactions/public-key")
    if response.status_code != 200:
        print(f"Failed to fetch public key. Status: {response.status_code}, Body: {response.text}")
        return
    public_key_pem = response.json()["public_key"]

    print("2. Generating ephemeral AES-256-GCM key...")
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12) 

    print("3. Encrypting JSON Payload with AES-GCM...")
    payload = {
        "user_id": user_id,
        "device_id": "test_device_e2e",
        "card_bin": "411111",
        "amount": 100.0,
        "currency": "MXN",
        "ip_address": "8.8.8.8",
        "latitude": 19.4326,
        "longitude": -99.1332,
        "transaction_type": "PAYMENT",
        "session_id": str(uuid.uuid4()),
        "user_agent": "python-crypto-test",
        "sdk_version": "v1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    plaintext = json.dumps(payload).encode('utf-8')
    combined_ciphertext = aesgcm.encrypt(iv, plaintext, associated_data=None)
    
    ciphertext = combined_ciphertext[:-16]
    auth_tag = combined_ciphertext[-16:]

    print("4. Encrypting AES Key with RSA Public Key...")
    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("5. Constructing EncryptedPayload and sending request...")
    encrypted_payload = {
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode('utf-8'),
        "iv": base64.b64encode(iv).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "auth_tag": base64.b64encode(auth_tag).decode('utf-8')
    }

    print("\n--- Sending request ---")
    post_resp = session.post(f"{API_BASE_URL}/transactions/evaluate", json=encrypted_payload)
    
    print(f"\nResponse Status: {post_resp.status_code}")
    print(f"Response JSON: {json.dumps(post_resp.json(), indent=2)}")

if __name__ == "__main__":
    test_encryption_flow()
