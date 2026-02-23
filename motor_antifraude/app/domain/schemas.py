from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field, IPvAnyAddress, UUID4, ConfigDict
from datetime import datetime
from decimal import Decimal

class TransactionType(str, Enum):
    TOP_UP = "TOP_UP"
    P2P_SEND = "P2P_SEND"
    WITHDRAWAL = "WITHDRAWAL"
    PAYMENT = "PAYMENT"

class ActionDecision(str, Enum):
    ACTION_APPROVE = "ACTION_APPROVE"
    ACTION_CHALLENGE_SOFT = "ACTION_CHALLENGE_SOFT"
    ACTION_CHALLENGE_HARD = "ACTION_CHALLENGE_HARD"
    ACTION_BLOCK_REVIEW = "ACTION_BLOCK_REVIEW"
    ACTION_BLOCK_PERM = "ACTION_BLOCK_PERM"

class ChallengeType(str, Enum):
    BIOMETRIC = "BIOMETRIC"
    SMS_OTP = "SMS_OTP"
    THREEDS = "3DS"
    FACE_SCAN = "FACE_SCAN"

class TransactionPayload(BaseModel):
    user_id: UUID4
    device_id: str = Field(..., min_length=1)
    card_bin: str = Field(..., min_length=6, max_length=8)
    amount: Decimal = Field(..., gt=0)
    currency: str = Field(..., min_length=3, max_length=3)
    ip_address: IPvAnyAddress
    latitude: float = Field(..., ge=-90, le=90)
    longitude: float = Field(..., ge=-180, le=180)
    transaction_type: TransactionType
    recipient_id: Optional[UUID4] = None
    session_id: UUID4
    timestamp: datetime
    user_agent: str = Field(..., min_length=1)
    sdk_version: str = Field(..., min_length=1)

    model_config = ConfigDict(extra="forbid")

class FraudEvaluationResponse(BaseModel):
    transaction_id: UUID4
    action: ActionDecision
    risk_score: int = Field(..., ge=0, le=100)
    challenge_type: Optional[ChallengeType] = None
    reason_codes: List[str]
    user_message: str
    response_time_ms: int = Field(..., ge=0)
    signature: str = Field(..., min_length=64)