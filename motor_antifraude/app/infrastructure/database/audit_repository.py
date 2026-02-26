"""
audit_repository.py
-------------------
Repositorio de auditoría de transacciones.

Responsabilidades:
  - Cifrar campos sensibles (device_id, card_bin, ip_address, payload)
    con AES-256-GCM antes de persistirlos.
  - Insertar un registro en `transaction_audit` por cada evaluación
    completada por el motor antifraude.

Principios de diseño:
  - save_evaluation NUNCA lanza excepciones hacia afuera: si falla
    solo loguea el error. Se llama desde _background_updates del
    orquestador, después de que la respuesta ya fue enviada al cliente.
  - Misma clave AES que face_service.py: sha256(SECRET_KEY)
    → un solo origen de verdad para la clave de cifrado de la app.
  - Formato de cifrado: nonce (12 bytes) + ciphertext + tag (16 bytes)
    Idéntico al usado en FaceService._encrypt / _decrypt.

Uso en el orquestador:
    repo = AuditRepository(db)
    await repo.save_evaluation(
        payload        = payload,
        final_score    = final_score,
        action         = action,
        response       = response,
    )
"""

import hashlib
import json
import logging
import os
import uuid
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.domain.models import TransactionAudit
from app.domain.schemas import (
    ActionDecision,
    FraudEvaluationResponse,
    TransactionPayload,
)

logger = logging.getLogger(__name__)

# ── Clave AES-256 derivada del SECRET_KEY ────────────────────────────
# Exactamente el mismo origen que face_service.py: sha256(SECRET_KEY).
# AES-256-GCM requiere 32 bytes exactos → sha256 produce 32 bytes.
_AES_KEY: bytes = hashlib.sha256(settings.SECRET_KEY.encode()).digest()


def _encrypt(data: bytes) -> bytes:
    """
    Cifra bytes con AES-256-GCM.

    Formato del output: nonce (12 bytes) + ciphertext + GCM tag (16 bytes).
    El nonce es aleatorio y único por llamada — se antepone al ciphertext
    para poder recuperarlo al momento de descifrar.

    Idéntico al patrón de FaceService._encrypt.
    """
    aesgcm     = AESGCM(_AES_KEY)
    nonce      = os.urandom(12)          # 96 bits — recomendado por NIST para GCM
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


class AuditRepository:
    """
    Encapsula el INSERT en `transaction_audit`.

    Se instancia por request con la sesión de DB inyectada desde el router.
    No es un singleton — la sesión es por-request.

    Ejemplo de uso:
        repo = AuditRepository(db)
        await repo.save_evaluation(payload, final_score, action, response)
    """

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def save_evaluation(
        self,
        payload:     TransactionPayload,
        final_score: int,
        action:      ActionDecision,
        response:    FraudEvaluationResponse,
    ) -> None:
        """
        Persiste el resultado de una evaluación antifraude en PostgreSQL.

        Cifra todos los campos sensibles antes de escribirlos:
          - device_id      → encrypted_device_id  (BYTEA)
          - card_bin       → encrypted_card_bin    (BYTEA)
          - ip_address     → parte del encrypted_payload (comparte cifrado)
          - payload JSON   → encrypted_payload     (BYTEA)

        La firma HMAC de la respuesta se guarda en claro porque es
        un hash no reversible — no expone datos sensibles.

        Si ocurre cualquier error, lo registra en el log y retorna sin
        propagar la excepción. Esto garantiza que un fallo de DB nunca
        afecte una evaluación ya entregada al cliente.
        """
        try:
            # ── Cifrar campos sensibles ───────────────────────────────
            encrypted_device_id = _encrypt(payload.device_id.encode())
            encrypted_card_bin  = _encrypt(payload.card_bin.encode())

            # Snapshot completo del payload para trazabilidad forense.
            # Serializar con json.dumps — ip_address y UUID necesitan str().
            payload_dict = {
                "user_id":          str(payload.user_id),
                "device_id":        payload.device_id,
                "card_bin":         payload.card_bin,
                "amount":           str(payload.amount),
                "currency":         payload.currency,
                "ip_address":       str(payload.ip_address),
                "latitude":         payload.latitude,
                "longitude":        payload.longitude,
                "transaction_type": payload.transaction_type,
                "recipient_id":     str(payload.recipient_id) if payload.recipient_id else None,
                "session_id":       str(payload.session_id),
                "timestamp":        payload.timestamp.isoformat(),
                "user_agent":       payload.user_agent,
                "sdk_version":      payload.sdk_version,
            }
            encrypted_payload = _encrypt(
                json.dumps(payload_dict, ensure_ascii=False).encode()
            )

            # ── Construir el registro de auditoría ────────────────────
            audit = TransactionAudit(
                id                = uuid.uuid4(),
                user_id           = payload.user_id,
                encrypted_device_id = encrypted_device_id,
                encrypted_card_bin  = encrypted_card_bin,
                action            = action.value,
                risk_score        = final_score,
                reason_codes      = response.reason_codes,
                transaction_type  = payload.transaction_type.value,
                amount            = payload.amount,
                currency          = payload.currency,
                encrypted_payload = encrypted_payload,
                response_signature = response.signature,
                response_time_ms  = response.response_time_ms,
            )

            # ── Persistir ─────────────────────────────────────────────
            self.db.add(audit)
            await self.db.commit()

            logger.info(
                f"[AuditRepository] INSERT OK — "
                f"audit_id={audit.id}  user={payload.user_id}  "
                f"action={action.value}  score={final_score}"
            )

        except Exception as exc:
            # Nunca propagar — esta función es fire-and-forget.
            # Un fallo de DB no debe afectar la respuesta ya enviada.
            logger.error(
                f"[AuditRepository] Error guardando auditoría "
                f"user={payload.user_id}: {exc}"
            )
            try:
                await self.db.rollback()
            except Exception:
                pass  # Si el rollback también falla, ignorar
