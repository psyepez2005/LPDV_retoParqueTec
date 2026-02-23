from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.core.config import settings
from app.infrastructure.cache.redis_client import redis_client
from app.api.routers import transactions

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await redis_client.aclose()

app = FastAPI(
    title="Motor Antifraude API",
    description="API de alta concurrencia para evaluacion de riesgo transaccional",
    version="1.0.0",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    lifespan=lifespan
)

app.include_router(transactions.router)

@app.get("/health")
async def health_check():
    return {"status": "ok", "environment": settings.ENVIRONMENT}