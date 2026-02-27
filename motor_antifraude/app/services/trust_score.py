import json
import logging
from dataclasses import dataclass, field
from typing import Optional

from redis.asyncio import Redis

logger = logging.getLogger(__name__)


REDUCTION_LONG_HISTORY    = -15
REDUCTION_MEDIUM_HISTORY  = -8
REDUCTION_KYC_FULL        = -7
REDUCTION_KYC_BASIC       = -3
REDUCTION_MFA_ACTIVE      = -5
REDUCTION_FREQUENT_DEVICE = -5
REDUCTION_TRUSTED_COUNTRY = -3

MAX_TOTAL_REDUCTION       = -25


@dataclass
class TrustProfile:
    user_id: str
    trust_reduction: int
    account_age_days: int
    kyc_level: str
    mfa_active: bool
    incident_free_months: int
    is_frequent_device: bool
    country_in_history: bool
    breakdown: dict = field(default_factory=dict)


class TrustScoreService:

    KEY_PREFIX = "trust:user"

    def __init__(self, redis_client: Redis):
        self.redis = redis_client

    async def get_trust_profile(
        self,
        user_id: str,
        device_id: str,
        country_code: Optional[str] = None,
    ) -> TrustProfile:
        prefix = f"{self.KEY_PREFIX}:{user_id}"

        keys = [
            f"{prefix}:account_age_days",
            f"{prefix}:kyc_level",
            f"{prefix}:mfa_active",
            f"{prefix}:incident_free_months",
            f"{prefix}:total_successful_tx",
            f"{prefix}:frequent_devices",
            f"{prefix}:frequent_countries",
        ]

        try:
            results = await self.redis.mget(*keys)
        except Exception as e:
            logger.error(f"[TrustScore] Redis error para user={user_id}: {e}")
            return self._neutral_profile(user_id)

        (
            raw_age, raw_kyc, raw_mfa,
            raw_incident_free, raw_total_tx,
            raw_devices, raw_countries,
        ) = results

        account_age_days     = int(raw_age)           if raw_age           else 0
        kyc_level            = raw_kyc.decode()       if raw_kyc           else "none"
        mfa_active           = raw_mfa == b"1"        if raw_mfa           else False
        incident_free_months = int(raw_incident_free) if raw_incident_free else 0

        is_frequent_device = False
        if raw_devices:
            try:
                frequent_devices   = json.loads(raw_devices)
                is_frequent_device = device_id in frequent_devices
            except (json.JSONDecodeError, TypeError):
                pass

        country_in_history = False
        if country_code and raw_countries:
            try:
                frequent_countries = json.loads(raw_countries)
                country_in_history = country_code in frequent_countries
            except (json.JSONDecodeError, TypeError):
                pass

        return self._calculate_reduction(
            user_id=user_id,
            account_age_days=account_age_days,
            kyc_level=kyc_level,
            mfa_active=mfa_active,
            incident_free_months=incident_free_months,
            is_frequent_device=is_frequent_device,
            country_in_history=country_in_history,
        )

    def _calculate_reduction(
        self,
        user_id: str,
        account_age_days: int,
        kyc_level: str,
        mfa_active: bool,
        incident_free_months: int,
        is_frequent_device: bool,
        country_in_history: bool,
    ) -> TrustProfile:
        breakdown = {}
        total = 0

        if incident_free_months >= 6:
            breakdown["long_history"]   = REDUCTION_LONG_HISTORY
            total                      += REDUCTION_LONG_HISTORY
        elif incident_free_months >= 2:
            breakdown["medium_history"] = REDUCTION_MEDIUM_HISTORY
            total                      += REDUCTION_MEDIUM_HISTORY

        if kyc_level == "full":
            breakdown["kyc_full"]  = REDUCTION_KYC_FULL
            total                 += REDUCTION_KYC_FULL
        elif kyc_level == "basic":
            breakdown["kyc_basic"] = REDUCTION_KYC_BASIC
            total                 += REDUCTION_KYC_BASIC

        if mfa_active:
            breakdown["mfa_active"] = REDUCTION_MFA_ACTIVE
            total                  += REDUCTION_MFA_ACTIVE

        if is_frequent_device:
            breakdown["frequent_device"] = REDUCTION_FREQUENT_DEVICE
            total                       += REDUCTION_FREQUENT_DEVICE

        if country_in_history:
            breakdown["trusted_country"] = REDUCTION_TRUSTED_COUNTRY
            total                       += REDUCTION_TRUSTED_COUNTRY

        final_reduction = max(total, MAX_TOTAL_REDUCTION)

        logger.debug(
            f"[TrustScore] user={user_id}  "
            f"reduction={final_reduction}  breakdown={breakdown}"
        )

        return TrustProfile(
            user_id=user_id,
            trust_reduction=final_reduction,
            account_age_days=account_age_days,
            kyc_level=kyc_level,
            mfa_active=mfa_active,
            incident_free_months=incident_free_months,
            is_frequent_device=is_frequent_device,
            country_in_history=country_in_history,
            breakdown=breakdown,
        )

    def _neutral_profile(self, user_id: str) -> TrustProfile:
        return TrustProfile(
            user_id=user_id,
            trust_reduction=0,
            account_age_days=0,
            kyc_level="none",
            mfa_active=False,
            incident_free_months=0,
            is_frequent_device=False,
            country_in_history=False,
            breakdown={},
        )

    async def record_successful_transaction(
        self,
        user_id: str,
        device_id: str,
        country_code: str,
    ) -> None:
        prefix = f"{self.KEY_PREFIX}:{user_id}"
        try:
            pipe = self.redis.pipeline()
            pipe.incr(f"{prefix}:total_successful_tx")
            pipe.expire(f"{prefix}:total_successful_tx", 60 * 60 * 24 * 180)
            await pipe.execute()
        except Exception as e:
            logger.error(
                f"[TrustScore] Error registrando tx exitosa user={user_id}: {e}"
            )

    async def reset_incident_free_counter(self, user_id: str) -> None:
        key = f"{self.KEY_PREFIX}:{user_id}:incident_free_months"
        try:
            await self.redis.set(key, "0")
            logger.info(
                f"[TrustScore] Contador reiniciado para user={user_id}"
            )
        except Exception as e:
            logger.error(
                f"[TrustScore] Error reiniciando contador user={user_id}: {e}"
            )