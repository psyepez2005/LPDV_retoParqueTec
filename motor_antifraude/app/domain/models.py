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

class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    username: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)

    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)

    cedula_hash: Mapped[bytes] = mapped_column(BYTEA, nullable=False, unique=True)
    cedula_last4: Mapped[str] = mapped_column(String(4), nullable=False)

    face_image_encrypted: Mapped[bytes] = mapped_column(BYTEA, nullable=True)

    face_encoding_encrypted: Mapped[bytes] = mapped_column(BYTEA, nullable=True)

    kyc_level: Mapped[str] = mapped_column(
        String(10), nullable=False, server_default="none"
    )

    mfa_active: Mapped[bool] = mapped_column(Boolean, default=False)

    incident_free_months: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )

    last_login_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_profile_change_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_suspended: Mapped[bool] = mapped_column(Boolean, default=False)

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


class TransactionAudit(Base):
    __tablename__ = "transaction_audit"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), index=True, nullable=False
    )

    encrypted_device_id: Mapped[bytes] = mapped_column(BYTEA, nullable=False)
    encrypted_card_bin: Mapped[bytes] = mapped_column(BYTEA, nullable=False)

    action: Mapped[str] = mapped_column(String(50), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    reason_codes: Mapped[list] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )

    transaction_type: Mapped[str] = mapped_column(String(20), nullable=False)

    amount: Mapped[float] = mapped_column(Numeric(18, 2), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)

    encrypted_payload: Mapped[bytes] = mapped_column(BYTEA, nullable=False)

    response_signature: Mapped[str] = mapped_column(String(64), nullable=False)

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

class DeviceHistory(Base):
    __tablename__ = "device_history"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False
    )

    encrypted_device_id: Mapped[bytes] = mapped_column(BYTEA, nullable=False)

    is_trusted: Mapped[bool] = mapped_column(Boolean, default=False)

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    successful_tx_count: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )

    __table_args__ = (
        Index("idx_device_history_user", "user_id"),
        Index("idx_device_history_user_trusted", "user_id", "is_trusted"),
    )


class Blacklist(Base):
    __tablename__ = "blacklist"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    entity_type: Mapped[str] = mapped_column(String(20), nullable=False)

    encrypted_entity_value: Mapped[bytes] = mapped_column(
        BYTEA, nullable=False, unique=True
    )

    reason: Mapped[str] = mapped_column(String(255), nullable=False)

    added_by: Mapped[str] = mapped_column(
        String(100), nullable=False, server_default="system"
    )

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

class OtpLog(Base):
    __tablename__ = "otp_log"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False
    )

    otp_hash: Mapped[bytes] = mapped_column(BYTEA, nullable=False)

    purpose: Mapped[str] = mapped_column(
        String(30), nullable=False, server_default="checkout"
    )

    status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="pending"
    )

    failed_attempts: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )

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