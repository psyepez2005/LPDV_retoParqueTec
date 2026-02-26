"""
dashboard.py — Router del Dashboard Antifraude
---------------------------------------------
Expone:
  GET  /v1/dashboard/summary          → Resumen completo para el dashboard
  GET  /v1/dashboard/summary?period_hours=N → Configurable por ventana de tiempo
  POST /v1/dashboard/merchants        → Registrar un nuevo comercio
  GET  /v1/dashboard/merchants        → Listar comercios activos
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.domain.models import Merchant
from app.domain.schemas import (
    DashboardSummary,
    MerchantCreate,
    MerchantResponse,
)
from app.infrastructure.database.dashboard_repository import DashboardRepository
from app.infrastructure.database.session import get_db

router = APIRouter(prefix="/v1/dashboard", tags=["Dashboard"])


# ── GET /v1/dashboard/summary ─────────────────────────────────────────

@router.get(
    "/summary",
    response_model=DashboardSummary,
    summary="Resumen completo del dashboard antifraude",
    description=(
        "Devuelve KPIs, feed transaccional, discrepancias geográficas, "
        "mapa de calor de comercios y alertas de identidad. "
        "Requiere autenticación JWT."
    ),
)
async def get_dashboard_summary(
    period_hours: int   = Query(24,  ge=1, le=168, description="Horas a analizar (1–168)"),
    feed_limit:   int   = Query(20,  ge=1, le=100, description="Máx. transacciones en el feed"),
    geo_limit:    int   = Query(30,  ge=1, le=100, description="Máx. discrepancias geo"),
    db:           AsyncSession  = Depends(get_db),
    _current_user = Depends(get_current_user),   # Requiere JWT válido
):
    repo = DashboardRepository(db)
    return await repo.get_summary(
        period_hours = period_hours,
        feed_limit   = feed_limit,
        geo_limit    = geo_limit,
    )


# ── POST /v1/dashboard/merchants ──────────────────────────────────────

@router.post(
    "/merchants",
    response_model=MerchantResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Registrar un nuevo comercio",
)
async def create_merchant(
    body:         MerchantCreate,
    db:           AsyncSession = Depends(get_db),
    _current_user = Depends(get_current_user),
):
    # Verificar duplicado por RUC
    if body.ruc:
        existing = await db.execute(
            select(Merchant).where(Merchant.ruc == body.ruc)
        )
        if existing.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Ya existe un comercio con RUC {body.ruc}.",
            )

    merchant = Merchant(
        id         = uuid.uuid4(),
        name       = body.name,
        ruc        = body.ruc,
        category   = body.category,
        is_active  = True,
        created_at = datetime.now(timezone.utc),
    )
    db.add(merchant)
    await db.commit()
    await db.refresh(merchant)

    return MerchantResponse(
        id         = str(merchant.id),
        name       = merchant.name,
        ruc        = merchant.ruc,
        category   = merchant.category,
        is_active  = merchant.is_active,
        created_at = merchant.created_at,
    )


# ── GET /v1/dashboard/merchants ───────────────────────────────────────

@router.get(
    "/merchants",
    response_model=list[MerchantResponse],
    summary="Listar todos los comercios activos",
)
async def list_merchants(
    db:           AsyncSession = Depends(get_db),
    _current_user = Depends(get_current_user),
):
    result = await db.execute(
        select(Merchant).where(Merchant.is_active == True).order_by(Merchant.name)
    )
    merchants = result.scalars().all()
    return [
        MerchantResponse(
            id         = str(m.id),
            name       = m.name,
            ruc        = m.ruc,
            category   = m.category,
            is_active  = m.is_active,
            created_at = m.created_at,
        )
        for m in merchants
    ]
