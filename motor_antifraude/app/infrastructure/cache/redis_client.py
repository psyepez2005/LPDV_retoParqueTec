import redis.asyncio as redis
from app.core.config import settings

redis_pool = redis.ConnectionPool.from_url(
    settings.REDIS_URL,
    decode_responses=True,
    max_connections=200,
    timeout=0.5
)

redis_client = redis.Redis(connection_pool=redis_pool)

async def get_redis_client() -> redis.Redis:
    return redis_client