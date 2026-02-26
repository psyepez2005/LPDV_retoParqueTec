import logging
from app.domain.schemas import TransactionPayload

logger = logging.getLogger(__name__)

# Script Lua que ejecuta INCR/INCRBYFLOAT/SADD y solo pone el TTL
# si la key acaba de ser creada (TTL == -1 significa sin expiración).
# Lua en Redis es atómico — no hay race condition entre el check y el set.
_LUA_SCRIPT = """
local vel_key   = KEYS[1]
local limit_key = KEYS[2]
local cards_key = KEYS[3]
local amount    = ARGV[1]
local card_bin  = ARGV[2]

local tx_count = redis.call('INCR', vel_key)
if redis.call('TTL', vel_key) == -1 then
    redis.call('EXPIRE', vel_key, 600)
end

local daily_total = redis.call('INCRBYFLOAT', limit_key, amount)
if redis.call('TTL', limit_key) == -1 then
    redis.call('EXPIRE', limit_key, 86400)
end

redis.call('SADD', cards_key, card_bin)
if redis.call('TTL', cards_key) == -1 then
    redis.call('EXPIRE', cards_key, 86400)
end

local distinct_cards = redis.call('SCARD', cards_key)

return {tx_count, daily_total, distinct_cards}
"""


class TopUpRulesEngine:

    async def evaluate(self, payload: TransactionPayload, redis_client) -> float:
        risk_penalty = 0.0
        user_id  = str(payload.user_id)
        card_bin = payload.card_bin
        amount   = float(payload.amount)

        velocity_key    = f"velocity:{user_id}:10m"
        daily_limit_key = f"limit:{user_id}:24h"
        cards_key       = f"cards:{user_id}:24h"

        # eval() ejecuta el script Lua de forma atómica en Redis
        # KEYS = las 3 keys, ARGV = amount y card_bin
        results = await redis_client.eval(
            _LUA_SCRIPT,
            3,                   # número de KEYS
            velocity_key,
            daily_limit_key,
            cards_key,
            str(amount),         # ARGV[1]
            card_bin,            # ARGV[2]
        )

        tx_count_10m   = int(results[0])
        daily_total    = float(results[1])
        distinct_cards = int(results[2])

        if tx_count_10m > 3:
            risk_penalty += 40.0
            logger.info(f"[TopUp] Alta velocidad: user={user_id} tx_10m={tx_count_10m}")

        if distinct_cards > 2:
            risk_penalty += 50.0
            logger.info(f"[TopUp] Múltiples BINs: user={user_id} cards={distinct_cards}")

        if daily_total > 500.0:
            risk_penalty += 30.0
            logger.info(f"[TopUp] Límite diario: user={user_id} total={daily_total}")

        return min(risk_penalty, 100.0)