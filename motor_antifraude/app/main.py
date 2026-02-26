"""
main.py
-------
Entry point del Motor Antifraude — Wallet Plux.

Orden de registro de middlewares (importa el orden — se ejecutan al revés):
  1. CORS            → primero en registrarse, último en ejecutarse
  2. SecurityHeaders → headers de seguridad en todas las respuestas
  3. GeoEnrichment   → enriquece el request con GeoIP y BIN antes del router
"""

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
    # ── Startup ───────────────────────────────────────────────────────
    await redis_manager.connect()
    if settings.DEBUG:
        await init_db()
    yield
    # ── Shutdown ──────────────────────────────────────────────────────
    await redis_manager.disconnect()


app = FastAPI(
    title    = "Motor Antifraude API",
    version  = "1.0.0",
    docs_url = "/docs"  if settings.DEBUG else None,
    redoc_url= "/redoc" if settings.DEBUG else None,
    lifespan = lifespan,
)

# ── Middlewares (registrar en este orden exacto) ──────────────────────

# 1. CORS — debe ser el primero para que los preflight pasen
setup_cors(app, allowed_origins=settings.ALLOWED_ORIGINS)

# 2. Security headers — aplica a todas las respuestas
app.add_middleware(SecurityHeadersMiddleware)

# 3. GeoEnrichment — enriquece el request antes de llegar al router
app.add_middleware(GeoEnrichmentMiddleware)

# ── Routers ───────────────────────────────────────────────────────────
app.include_router(transactions.router)
app.include_router(auth.router)
app.include_router(dashboard.router)

# ── Handler global de excepciones ────────────────────────────────────
@app.exception_handler(FraudMotorException)
async def fraud_exception_handler(
    request: Request, exc: FraudMotorException
) -> JSONResponse:
    return JSONResponse(
        status_code = exc.status_code,
        content     = {"error": exc.message},
    )

# ── Health check ──────────────────────────────────────────────────────
@app.get("/health")
async def health_check():
    redis_ok = await redis_manager.ping()
    return {
        "status":      "ok",
        "environment": settings.ENVIRONMENT,
        "redis":       "ok" if redis_ok else "degraded",
    }