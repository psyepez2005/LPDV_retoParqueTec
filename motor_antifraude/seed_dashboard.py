import asyncio
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from sqlalchemy import select, text
from faker import Faker

# Ajustamos para poder ejecutar este script directamente desde la raíz
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.domain.models import Merchant, TransactionAudit
from app.infrastructure.database.session import AsyncSessionLocal
from app.infrastructure.database.audit_repository import _encrypt

fake = Faker()

MERCHANTS = [
    {"name": "Maxiplus S.A.", "ruc": "1791234560001", "category": "ECOMMERCE"},
    {"name": "Aki Tiendas", "ruc": "1790987650001", "category": "POS"},
    {"name": "TuPrecio Online", "ruc": "1792345670001", "category": "ECOMMERCE"},
    {"name": "FarmaExpress", "ruc": "1793456780001", "category": "POS"},
    {"name": "Kiwi Market", "ruc": "1794567890001", "category": "ECOMMERCE"}
]

COUNTRIES = ["EC", "US", "MX", "CO", "ES", "RU", "CN", "PE"]

async def seed():
    async with AsyncSessionLocal() as db:
        print("==> Ejecutando Seeder del Dashboard <==")
        
        # 1. Asegurar Merchants
        print("Validando comercios...")
        merchant_objs = []
        for m_data in MERCHANTS:
            res = await db.execute(select(Merchant).where(Merchant.ruc == m_data["ruc"]))
            m = res.scalar_one_or_none()
            if not m:
                m = Merchant(
                    id=uuid.uuid4(),
                    name=m_data["name"],
                    ruc=m_data["ruc"],
                    category=m_data["category"]
                )
                db.add(m)
            merchant_objs.append(m)
        
        await db.commit()
        for m in merchant_objs:
            await db.refresh(m)

        print(f"Generando 150 transacciones de prueba históricas (últimas 48h)...")
        # 2. Generar Transacciones
        
        # Simulamos 5 usuarios "frecuentes" y 20 usuarios "esporádicos"
        frequent_users = [uuid.uuid4() for _ in range(5)]
        casual_users = [uuid.uuid4() for _ in range(20)]
        all_users = frequent_users + casual_users
        
        transactions_added = 0
        
        for i in range(150):
            merchant = random.choice(merchant_objs)
            # 30% de las transacciones son de usuarios frecuentes
            user_id = random.choice(frequent_users) if random.random() < 0.3 else random.choice(casual_users)
            
            # Tiempo distribuido en las últimas 48 horas
            created_at = datetime.now(timezone.utc) - timedelta(hours=random.randint(0, 48), minutes=random.randint(0, 59))
            
            # Decidir si es fraude (15% de probabilidad)
            is_fraud = random.random() < 0.15
            
            if is_fraud:
                action = random.choice(["ACTION_BLOCK_PERM", "ACTION_BLOCK_REVIEW", "ACTION_CHALLENGE_HARD"])
                risk_score = random.randint(70, 99)
                ip_country = random.choice(["RU", "CN", "NG", "US"])
                gps_country = random.choice(["EC", "CO", "PE"])
                
                # Crear algunos reason_codes creíbles
                reason_codes = [
                    {"code": "VPN_DETECTED", "points": 25, "category": "Dispositivo", "description": "Conexión a través de VPN o Proxy identificada."},
                    {"code": "DUAL_COUNTRY_MISMATCH", "points": 30, "category": "Geolocalización", "description": "El país de la IP y el GPS no coinciden."},
                    {"code": "__DEVICE_BASE__", "points": 15, "category": "Dispositivo", "description": "Score base del modelo de dispositivo."}
                ]
                
                # Para fraude, un 20% de probabilidad de ser alto valor
                amount = random.uniform(800.0, 3000.0) if random.random() < 0.2 else random.uniform(10.0, 300.0)
            else:
                action = "ACTION_APPROVE"
                risk_score = random.randint(0, 25)
                # Usuarios normales usualmente están en el mismo país
                ip_country = random.choice(["EC", "CO", "MX", "PE"])
                gps_country = ip_country
                reason_codes = [
                    {"code": "__VELOCITY_BASE__", "points": 5, "category": "Comportamiento", "description": "Score base de velocidad de transacciones."},
                ]
                amount = random.uniform(5.0, 400.0)
                
            amount_dec = Decimal(round(amount, 2))
            
            device_id = fake.uuid4()
            
            # Para testear Identity Risks, hacemos que usuarios frecuentes a veces usen distintas tarjetas
            if user_id in frequent_users and random.random() < 0.4:
                card_bin = str(random.choice([411111, 524356, 378282, 601100, 356600, 650031]))
            else:
                card_bin = str(random.randint(400000, 499999))
            
            payload_dict = {
                "user_id": str(user_id),
                "device_id": device_id,
                "card_bin": card_bin,
                "amount": str(amount_dec),
                "currency": "USD",
                "ip_address": fake.ipv4(),
                "latitude": float(fake.latitude()),
                "longitude": float(fake.longitude()),
                "transaction_type": "PAYMENT",
                "session_id": str(uuid.uuid4()),
                "timestamp": created_at.isoformat(),
                "user_agent": fake.user_agent(),
                "sdk_version": "1.0.0",
                "merchant_id": str(merchant.id),
                "merchant_name": merchant.name,
                "ip_country": ip_country
            }
            
            audit = TransactionAudit(
                id=uuid.uuid4(),
                user_id=user_id,
                encrypted_device_id=_encrypt(device_id.encode()),
                encrypted_card_bin=_encrypt(card_bin.encode()),
                action=action,
                risk_score=risk_score,
                reason_codes=reason_codes,
                transaction_type="PAYMENT",
                amount=amount_dec,
                currency="USD",
                encrypted_payload=_encrypt(json.dumps(payload_dict, ensure_ascii=False).encode()),
                response_signature=fake.sha256(),
                response_time_ms=random.randint(40, 350),
                merchant_id=merchant.id,
                merchant_name=merchant.name,
                ip_country=ip_country,
                gps_country=gps_country,
                created_at=created_at
            )
            db.add(audit)
            transactions_added += 1
        
        await db.commit()
        print(f"Exito. {transactions_added} transacciones simuladas agregadas correctamente a la base de datos.")

if __name__ == "__main__":
    asyncio.run(seed())
