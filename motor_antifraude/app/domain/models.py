import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, Boolean, text, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB, BYTEA
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

class Base(DeclarativeBase):
    pass

class TransactionAudit(Base):
    __tablename__ = "transaction_audit"

    # Almacenamiento inmutable para cumplimiento PCI DSS Req. 10
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True, nullable=False)
    
    # Los campos sensibles se definen como BYTEA para almacenar el output cifrado en AES-256-GCM
    encrypted_device_id: Mapped[bytes] = mapped_column(BYTEA, nullable=False)
    encrypted_card_bin: Mapped[bytes] = mapped_column(BYTEA, nullable=False)
    
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    reason_codes: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    
    # Snapshot del payload original para trazabilidad
    encrypted_payload: Mapped[bytes] = mapped_column(BYTEA, nullable=False)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_audit_user_created", "user_id", "created_at"),
    )

class DeviceHistory(Base):
    __tablename__ = "device_history"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    
    encrypted_device_id: Mapped[bytes] = mapped_column(BYTEA, nullable=False)
    
    is_trusted: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_device_history_user", "user_id"),
    )

class Blacklist(Base):
    __tablename__ = "blacklist"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_type: Mapped[str] = mapped_column(String(20), nullable=False) 
    encrypted_entity_value: Mapped[bytes] = mapped_column(BYTEA, nullable=False, unique=True)
    
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))