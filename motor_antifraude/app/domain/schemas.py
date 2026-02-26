"""
schemas.py
----------
Schemas Pydantic para validación de requests y responses.
"""

from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field, IPvAnyAddress, UUID4, ConfigDict, EmailStr, field_validator
from datetime import datetime
from decimal import Decimal
import re


# ─────────────────────────────────────────────────────────────────────
# ENUMS
# ─────────────────────────────────────────────────────────────────────

class TransactionType(str, Enum):
    TOP_UP     = "TOP_UP"
    P2P_SEND   = "P2P_SEND"
    WITHDRAWAL = "WITHDRAWAL"
    PAYMENT    = "PAYMENT"


class ActionDecision(str, Enum):
    ACTION_APPROVE        = "ACTION_APPROVE"
    ACTION_CHALLENGE_SOFT = "ACTION_CHALLENGE_SOFT"
    ACTION_CHALLENGE_HARD = "ACTION_CHALLENGE_HARD"
    ACTION_BLOCK_REVIEW   = "ACTION_BLOCK_REVIEW"
    ACTION_BLOCK_PERM     = "ACTION_BLOCK_PERM"


class ChallengeType(str, Enum):
    BIOMETRIC = "BIOMETRIC"
    SMS_OTP   = "SMS_OTP"
    THREEDS   = "3DS"
    FACE_SCAN = "FACE_SCAN"


# ─────────────────────────────────────────────────────────────────────
# TRANSACCIONES
# ─────────────────────────────────────────────────────────────────────

class DeviceOS(str, Enum):
    ANDROID = "android"
    IOS     = "ios"
    WEB     = "web"
    UNKNOWN = "unknown"

class NetworkType(str, Enum):
    WIFI    = "wifi"
    FOUR_G  = "4g"
    THREE_G = "3g"
    VPN     = "vpn"
    UNKNOWN = "unknown"

class KycLevel(str, Enum):
    NONE  = "none"
    BASIC = "basic"
    FULL  = "full"

class MerchantCategory(str, Enum):
    ECOMMERCE   = "ECOMMERCE"
    ATM         = "ATM"
    POS         = "POS"
    TRANSFER    = "TRANSFER"
    SUBSCRIPTION = "SUBSCRIPTION"
    UNKNOWN     = "UNKNOWN"


class TransactionPayload(BaseModel):
    # ── Campos base (obligatorios) ─────────────────────────────────────
    user_id:          UUID4
    device_id:        str            = Field(..., min_length=1)
    card_bin:         str            = Field(..., min_length=6, max_length=8)
    amount:           Decimal        = Field(..., gt=0)
    currency:         str            = Field(..., min_length=3, max_length=3)
    ip_address:       IPvAnyAddress
    latitude:         float          = Field(..., ge=-90,  le=90)
    longitude:        float          = Field(..., ge=-180, le=180)
    transaction_type: TransactionType
    recipient_id:     Optional[UUID4] = None
    session_id:       UUID4
    timestamp:        datetime
    user_agent:       str            = Field(..., min_length=1)
    sdk_version:      str            = Field(..., min_length=1)

    # ── Contexto del dispositivo (opcionales) ──────────────────────────
    device_os:        DeviceOS       = DeviceOS.UNKNOWN
    device_model:     Optional[str]  = None
    is_rooted_device: bool           = False
    is_emulator:      bool           = False
    network_type:     NetworkType    = NetworkType.UNKNOWN
    battery_level:    Optional[int]  = Field(None, ge=0, le=100)

    # ── Historial del usuario (opcionales) ────────────────────────────
    account_age_days:          Optional[int]     = Field(None, ge=0)
    avg_monthly_amount:        Optional[Decimal] = Field(None, ge=0)
    tx_count_last_30_days:     Optional[int]     = Field(None, ge=0)
    failed_tx_last_7_days:     Optional[int]     = Field(None, ge=0)
    time_since_last_tx_minutes: Optional[int]   = Field(None, ge=0)
    kyc_level:                 KycLevel          = KycLevel.NONE

    # ── Contexto de sesión / red (opcionales) ─────────────────────────
    session_duration_seconds:  Optional[int] = Field(None, ge=0)
    # Tiempo (segundos) que el usuario tardó en llenar el formulario de pago.
    # < 3s → scripting/bot, > 900s → sesión abandonada o reutilizada.
    form_fill_time_seconds:    Optional[int] = Field(None, ge=0)

    # ── Contexto de tarjeta / pago (opcionales) ───────────────────────
    card_last4:           Optional[str]             = Field(None, min_length=4, max_length=4)
    is_international_card: bool                     = False
    merchant_category:    MerchantCategory          = MerchantCategory.UNKNOWN

    model_config = ConfigDict(extra="ignore")




class ScoreEntry(BaseModel):
    """
    Explicación detallada de un factor de riesgo individual.
    Uno por cada reason_code activo en la evaluación.
    """
    code:        str   # Código interno del factor (e.g. SESSION_REPLAY_ATTACK)
    points:      int   # Puntos que este factor sumó al score (0 si es informativo)
    category:    str   # Módulo que lo detectó (e.g. "Sesión", "Dispositivo")
    description: str   # Explicación en lenguaje natural del motivo


class FraudEvaluationResponse(BaseModel):
    transaction_id:   UUID4
    action:           ActionDecision
    risk_score:       int            = Field(..., ge=0, le=100)
    challenge_type:   Optional[ChallengeType] = None
    reason_codes:     List[str]
    score_breakdown:  List[ScoreEntry] = Field(
        default_factory=list,
        description="Desglose detallado de cada factor que contribuyó al score"
    )
    user_message:     str
    response_time_ms: int            = Field(..., ge=0)
    signature:        str            = Field(..., min_length=64)


# ─────────────────────────────────────────────────────────────────────
# AUTENTICACIÓN — REGISTRO
# ─────────────────────────────────────────────────────────────────────

class UserRegisterRequest(BaseModel):
    """
    Schema de registro de usuario.
    La foto de cara se recibe como multipart/form-data en el router,
    no en este schema JSON — FastAPI la maneja con UploadFile.
    """
    email:            EmailStr
    username:         str      = Field(..., min_length=3, max_length=50)
    password:         str      = Field(..., min_length=8, max_length=100)
    cedula:           str      = Field(..., min_length=6, max_length=20)

    @field_validator("username")
    @classmethod
    def username_alphanumeric(cls, v: str) -> str:
        """Solo letras, números, guiones y guiones bajos."""
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError(
                "El usuario solo puede contener letras, números, _ y -"
            )
        return v.lower()

    @field_validator("cedula")
    @classmethod
    def cedula_numeric(cls, v: str) -> str:
        """Solo dígitos numéricos."""
        if not v.isdigit():
            raise ValueError("La cédula solo debe contener números.")
        return v

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        """Contraseña debe tener al menos una mayúscula, una minúscula y un número."""
        if not re.search(r'[A-Z]', v):
            raise ValueError("La contraseña debe tener al menos una mayúscula.")
        if not re.search(r'[a-z]', v):
            raise ValueError("La contraseña debe tener al menos una minúscula.")
        if not re.search(r'\d', v):
            raise ValueError("La contraseña debe tener al menos un número.")
        return v

    model_config = ConfigDict(extra="forbid")


class UserRegisterResponse(BaseModel):
    """Respuesta al registrar un usuario exitosamente."""
    user_id:  UUID4
    email:    str
    username: str
    message:  str = "Cuenta creada exitosamente."


# ─────────────────────────────────────────────────────────────────────
# AUTENTICACIÓN — LOGIN
# ─────────────────────────────────────────────────────────────────────

class UserLoginRequest(BaseModel):
    email:    EmailStr
    password: str = Field(..., min_length=1)

    model_config = ConfigDict(extra="forbid")


class UserLoginResponse(BaseModel):
    """Respuesta al hacer login exitosamente."""
    access_token:  str
    token_type:    str = "bearer"
    expires_in:    int          # Segundos hasta que expira el token
    user_id:       UUID4
    username:      str


# ─────────────────────────────────────────────────────────────────────
# AUTENTICACIÓN — USUARIO ACTUAL
# ─────────────────────────────────────────────────────────────────────

class CurrentUser(BaseModel):
    """
    Datos del usuario autenticado extraídos del JWT.
    Se inyecta en los routers via Depends(get_current_user).
    """
    user_id:   UUID4
    email:     str
    username:  str
    kyc_level: str


# ─────────────────────────────────────────────────────────────────────
# CHECKOUT
# ─────────────────────────────────────────────────────────────────────

class CheckoutInitiateRequest(BaseModel):
    """
    Datos del formulario de checkout.
    El email no se pide — se extrae del JWT del usuario autenticado.
    """
    amount:           Decimal        = Field(..., gt=0)
    currency:         str            = Field(..., min_length=3, max_length=3)
    card_bin:         str            = Field(..., min_length=6, max_length=8)
    card_last4:       str            = Field(..., min_length=4, max_length=4)
    device_id:        str            = Field(..., min_length=1)
    latitude:         float          = Field(..., ge=-90,  le=90)
    longitude:        float          = Field(..., ge=-180, le=180)
    transaction_type: TransactionType = TransactionType.PAYMENT
    recipient_id:     Optional[UUID4] = None

    model_config = ConfigDict(extra="forbid")


class CheckoutInitiateResponse(BaseModel):
    """Respuesta al iniciar el checkout — indica que se envió el OTP."""
    message:    str  = "Código de verificación enviado a tu correo."
    expires_in: int  = 300   # Segundos (5 minutos)


class OtpVerifyRequest(BaseModel):
    """OTP ingresado por el usuario."""
    otp_code: str = Field(..., min_length=6, max_length=6)

    @field_validator("otp_code")
    @classmethod
    def otp_numeric(cls, v: str) -> str:
        if not v.isdigit():
            raise ValueError("El código OTP solo debe contener números.")
        return v

    model_config = ConfigDict(extra="forbid")


class CheckoutDecisionResponse(BaseModel):
    """
    Respuesta final del checkout después de validar el OTP
    y evaluar el riesgo.
    """
    action:          ActionDecision
    risk_score:      int
    user_message:    str
    transaction_id:  Optional[UUID4] = None
    challenge_type:  Optional[ChallengeType] = None
    requires_liveness: bool = False   # True cuando score 21-70 → prueba de vida