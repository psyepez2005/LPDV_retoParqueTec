import redis.asyncio as redis
from app.core.config import settings

class RedisManager:
    def __init__(self):
        self.client: redis.Redis | None = None

    async def connect(self):
        self.client = redis.Redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            max_connections=200,
            socket_timeout=0.5
        )

    async def disconnect(self):
        if self.client:
            await self.client.aclose()

redis_manager = RedisManager()