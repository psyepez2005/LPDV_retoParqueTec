from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.exceptions import FraudMotorException
from app.infrastructure.cache.redis_client import redis_manager
from app.infrastructure.database.session import init_db
from app.api.routers import transactions
from app.api.routers import auth
from app.api.routers import dashboard
from app.api.middlewares import (
    GeoEnrichmentMiddleware,
    SecurityHeadersMiddleware,
    setup_cors,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await redis_manager.connect()
    if settings.DEBUG:
        await init_db()
    yield
    await redis_manager.disconnect()


app = FastAPI(
    title    = "Motor Antifraude API",
    version  = "1.0.0",
    docs_url = "/docs"  if settings.DEBUG else None,
    redoc_url= "/redoc" if settings.DEBUG else None,
    lifespan = lifespan,
)

# Middlewares — registrar en este orden (CORS primero, ejecuta último)
setup_cors(app, allowed_origins=settings.ALLOWED_ORIGINS)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(GeoEnrichmentMiddleware)

app.include_router(transactions.router)
app.include_router(auth.router)
app.include_router(dashboard.router)


@app.exception_handler(FraudMotorException)
async def fraud_exception_handler(
    request: Request, exc: FraudMotorException
) -> JSONResponse:
    return JSONResponse(
        status_code = exc.status_code,
        content     = {"error": exc.message},
    )


@app.get("/health")
async def health_check():
    redis_ok = await redis_manager.ping()
    return {
        "status":      "ok",
        "environment": settings.ENVIRONMENT,
        "redis":       "ok" if redis_ok else "degraded",
    }