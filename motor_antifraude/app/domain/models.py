"""
models.py
---------
Modelos SQLAlchemy para el Motor Antifraude — Wallet Plux.

Tablas:
  - User              → perfil del usuario, KYC, trust score
  - TransactionAudit  → registro inmutable de cada evaluación (PCI DSS Req.10)
  - DeviceHistory     → historial de dispositivos por usuario
  - Blacklist         → entidades bloqueadas permanente o temporalmente
  - OtpLog            → registro de OTPs emitidos para el flujo de checkout

Principios de diseño:
  - Campos sensibles como BYTEA → almacenan output cifrado AES-256-GCM
  - Todos los IDs son UUID v4 → no secuenciales, no predecibles
  - created_at siempre con timezone=True → auditoría correcta
  - Índices en columnas de búsqueda frecuente → performance en consultas
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import BYTEA, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


# ─────────────────────────────────────────────────────────────────────
# USUARIOS
# Perfil base del usuario. El motor lee de aquí para construir el
# TrustScore y el BehaviorProfile que se cachean en Redis.
# ─────────────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # Datos de identidad — almacenados con hash SHA-256 + salt (PII)
    email_hash: Mapped[bytes] = mapped_column(BYTEA, nullable=False, unique=True)
    phone_hash: Mapped[bytes] = mapped_column(BYTEA, nullable=True)

    # Nivel de verificación KYC
    # "none" → sin verificar
    # "basic" → email + teléfono verificados
    # "full"  → documento de identidad + biometría verificados
    kyc_level: Mapped[str] = mapped_column(
        String(10), nullable=False, server_default="none"
    )

    # Autenticación multifactor
    mfa_active: Mapped[bool] = mapped_column(Boolean, default=False)

    # Meses consecutivos sin incidentes de fraude confirmado
    # El worker nocturno incrementa este contador mensualmente
    # Se reinicia a 0 cuando un analista confirma un fraude real
    incident_free_months: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )

    # Timestamps de eventos críticos para el BehaviorEngine
    last_login_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_profile_change_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Estado de la cuenta
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_suspended: Mapped[bool] = mapped_column(Boolean, default=False)

    # Timestamps de ciclo de vida
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index("idx_users_created_at", "created_at"),
        Index("idx_users_kyc_level", "kyc_level"),
    )


# ─────────────────────────────────────────────────────────────────────
# AUDITORÍA DE TRANSACCIONES
# Registro inmutable de cada evaluación del motor.
# PCI DSS Req. 10: logs de auditoría retenidos mínimo 12 meses.
# Nunca se actualiza ni se borra — solo INSERT.
# ─────────────────────────────────────────────────────────────────────
class TransactionAudit(Base):
    __tablename__ = "transaction_audit"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), index=True, nullable=False
    )

    # Campos sensibles cifrados con AES-256-GCM
    encrypted_device_id: Mapped[bytes] = mapped_column(BYTEA, nullable=False)
    encrypted_card_bin: Mapped[bytes] = mapped_column(BYTEA, nullable=False)

    # Resultado de la evaluación
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    reason_codes: Mapped[list] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )

    # Tipo de transacción evaluada
    transaction_type: Mapped[str] = mapped_column(String(20), nullable=False)

    # Monto como Numeric para precisión exacta (sin errores de float)
    amount: Mapped[float] = mapped_column(Numeric(18, 2), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)

    # Snapshot cifrado del payload completo para trazabilidad forense
    encrypted_payload: Mapped[bytes] = mapped_column(BYTEA, nullable=False)

    # Firma HMAC-SHA256 de la respuesta emitida
    response_signature: Mapped[str] = mapped_column(String(64), nullable=False)

    # Tiempo de procesamiento en ms (para monitoreo de SLA)
    response_time_ms: Mapped[int] = mapped_column(Integer, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index("idx_audit_user_created", "user_id", "created_at"),
        Index("idx_audit_action", "action"),
        Index("idx_audit_risk_score", "risk_score"),
    )


# ─────────────────────────────────────────────────────────────────────
# HISTORIAL DE DISPOSITIVOS
# Registro de cada dispositivo asociado a un usuario.
# El motor usa esto para distinguir "dispositivo conocido" de "nuevo".
# ─────────────────────────────────────────────────────────────────────
class DeviceHistory(Base):
    __tablename__ = "device_history"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False
    )

    # device_id cifrado — nunca en texto plano en la DB
    encrypted_device_id: Mapped[bytes] = mapped_column(BYTEA, nullable=False)

    # True cuando el usuario verificó explícitamente este dispositivo
    # (ej. confirmó OTP desde este dispositivo por primera vez)
    is_trusted: Mapped[bool] = mapped_column(Boolean, default=False)

    # Timestamps de primera y última vez visto
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Número de transacciones exitosas desde este dispositivo
    # El worker nocturno lo incrementa — el motor lo lee para Trust Score
    successful_tx_count: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )

    __table_args__ = (
        Index("idx_device_history_user", "user_id"),
        Index("idx_device_history_user_trusted", "user_id", "is_trusted"),
    )


# ─────────────────────────────────────────────────────────────────────
# BLACKLIST
# Entidades bloqueadas. Redis es la fuente primaria para velocidad,
# PostgreSQL es el respaldo permanente para auditoría y recovery.
# Si Redis se reinicia, el worker de startup recarga desde aquí.
# ─────────────────────────────────────────────────────────────────────
class Blacklist(Base):
    __tablename__ = "blacklist"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # "user" | "device" | "ip" | "bin" | "email" | "phone"
    entity_type: Mapped[str] = mapped_column(String(20), nullable=False)

    # Valor cifrado de la entidad bloqueada
    encrypted_entity_value: Mapped[bytes] = mapped_column(
        BYTEA, nullable=False, unique=True
    )

    # Razón del bloqueo para auditoría
    reason: Mapped[str] = mapped_column(String(255), nullable=False)

    # Quién agregó el bloqueo: "system" | "analyst:{user_id}"
    added_by: Mapped[str] = mapped_column(
        String(100), nullable=False, server_default="system"
    )

    # None = permanente, fecha = expira automáticamente
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index("idx_blacklist_type_active", "entity_type", "is_active"),
    )


# ─────────────────────────────────────────────────────────────────────
# OTP LOG
# Registro de códigos OTP emitidos para el flujo de checkout.
# Redis guarda el OTP activo (TTL 5 min), PostgreSQL guarda el historial
# para auditoría y detección de abuso (ej. muchos OTPs para un usuario).
# ─────────────────────────────────────────────────────────────────────
class OtpLog(Base):
    __tablename__ = "otp_log"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False
    )

    # Hash del OTP — nunca el OTP en texto plano en la DB
    otp_hash: Mapped[bytes] = mapped_column(BYTEA, nullable=False)

    # Propósito del OTP
    # "checkout" | "login" | "profile_change"
    purpose: Mapped[str] = mapped_column(
        String(30), nullable=False, server_default="checkout"
    )

    # Estado del OTP
    # "pending" | "used" | "expired" | "cancelled"
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="pending"
    )

    # Número de intentos fallidos (máx 3 antes de cancelar)
    failed_attempts: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )

    # IP desde donde se solicitó el OTP (para detección de abuso)
    encrypted_ip: Mapped[bytes] = mapped_column(BYTEA, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("idx_otp_user_status", "user_id", "status"),
        Index("idx_otp_created_at", "created_at"),
    )