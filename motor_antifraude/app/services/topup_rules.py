import redis.asyncio as redis
from app.domain.schemas import TransactionPayload
from app.infrastructure.cache.redis_client import get_redis_client

class TopUpRulesEngine:
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client

    async def evaluate(self, payload: TransactionPayload) -> float:
        risk_penalty = 0.0
        
        user_id = str(payload.user_id)
        card_bin = payload.card_bin
        amount = float(payload.amount)

        velocity_key = f"velocity:{user_id}:10m"
        daily_limit_key = f"limit:{user_id}:24h"
        cards_key = f"cards:{user_id}:24h"
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.incr(velocity_key)
            pipe.expire(velocity_key, 600, nx=True)

            pipe.incrbyfloat(daily_limit_key, amount)
            pipe.expire(daily_limit_key, 86400, nx=True)

            pipe.sadd(cards_key, card_bin)
            pipe.expire(cards_key, 86400, nx=True)
            pipe.scard(cards_key)

            results = await pipe.execute()

        tx_count_10m = results[0]
        daily_total = results[2]
        distinct_cards_count = results[6]

        if tx_count_10m > 3:
            risk_penalty += 40.0

        if distinct_cards_count > 2:
            risk_penalty += 50.0

        if daily_total > 500.0:
            risk_penalty += 30.0

        return min(risk_penalty, 100.0)