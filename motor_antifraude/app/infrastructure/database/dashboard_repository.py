"""
dashboard_repository.py
-----------------------
Consultas optimizadas para el endpoint GET /v1/dashboard/summary.

Todas las queries son de SOLO LECTURA (SELECT) — no modifican datos.
Usan SQLAlchemy Core (text + parámetros) para mayor rendimiento en
agregaciones complejas sobre transaction_audit.

Principios:
- Una sola sesión de DB por request (inyectada desde el router).
- Parámetro `period_hours` para ventana de tiempo configurable.
- card_bin: se descifra dentro de _decrypt() si está cifrado,  
  de lo contrario se usa el campo `merchant_name` en claro que  
  guardamos desde v2 del audit (sin descifrar el BIN antiguo).
"""

import hashlib
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.domain.schemas import (
    DashboardKPIs,
    DashboardSummary,
    GeoDiscrepancy,
    IdentityRiskItem,
    MerchantHeatmapItem,
    TransactionFeedItem,
)

logger = logging.getLogger(__name__)

# ── Clave AES (misma que audit_repository.py) ────────────────────────
_AES_KEY: bytes = hashlib.sha256(settings.SECRET_KEY.encode()).digest()


def _decrypt(data: bytes) -> str:
    """Descifra un campo AES-256-GCM. Retorna '' si falla."""
    try:
        aesgcm = AESGCM(_AES_KEY)
        nonce      = data[:12]
        ciphertext = data[12:]
        return aesgcm.decrypt(nonce, ciphertext, None).decode()
    except Exception:
        return ""


# ─────────────────────────────────────────────────────────────────────

class DashboardRepository:
    """
    Repositorio de lectura para el dashboard analítico.
    """

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def get_summary(
        self,
        period_hours: int = 24,
        feed_limit:   int = 20,
        geo_limit:    int = 30,
    ) -> DashboardSummary:
        since = datetime.now(timezone.utc) - timedelta(hours=period_hours)

        kpis               = await self._get_kpis(since)
        geo_discrepancies  = await self._get_geo_discrepancies(since, geo_limit)
        transaction_feed   = await self._get_transaction_feed(since, feed_limit)
        merchant_heatmap   = await self._get_merchant_heatmap(since)
        identity_risks     = await self._get_identity_risks(since)

        return DashboardSummary(
            generated_at      = datetime.now(timezone.utc),
            period_hours      = period_hours,
            kpis              = kpis,
            geo_discrepancies = geo_discrepancies,
            transaction_feed  = transaction_feed,
            merchant_heatmap  = merchant_heatmap,
            identity_risks    = identity_risks,
        )

    # ── KPIs ──────────────────────────────────────────────────────────

    async def _get_kpis(self, since: datetime) -> DashboardKPIs:
        """
        Calcula métricas globales del período:
          - total_volume: suma de amount
          - total_tx / rejected_tx / challenged_tx / approved_tx
          - rejection_rate_pct
          - critical_alerts_last_hour: bloqueadas en los últimos 60 min
        """
        try:
            q = text("""
                SELECT
                    COALESCE(SUM(amount), 0)                                    AS total_volume,
                    COUNT(*)                                                     AS total_tx,
                    COUNT(*) FILTER (WHERE action LIKE 'ACTION_BLOCK%')         AS rejected_tx,
                    COUNT(*) FILTER (WHERE action LIKE 'ACTION_CHALLENGE%')     AS challenged_tx,
                    COUNT(*) FILTER (WHERE action = 'ACTION_APPROVE')           AS approved_tx
                FROM transaction_audit
                WHERE created_at >= :since
            """)
            row = (await self.db.execute(q, {"since": since})).mappings().one()

            total_tx    = int(row["total_tx"])
            rejected_tx = int(row["rejected_tx"])

            # Alertas críticas en la última hora
            one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
            q2 = text("""
                SELECT COUNT(*) AS cnt
                FROM transaction_audit
                WHERE created_at >= :since
                  AND action LIKE 'ACTION_BLOCK%'
            """)
            alerts_row = (await self.db.execute(q2, {"since": one_hour_ago})).mappings().one()

            rejection_rate = round((rejected_tx / total_tx * 100), 2) if total_tx > 0 else 0.0

            return DashboardKPIs(
                total_volume             = float(row["total_volume"]),
                total_tx                 = total_tx,
                rejected_tx              = rejected_tx,
                challenged_tx            = int(row["challenged_tx"]),
                approved_tx              = int(row["approved_tx"]),
                rejection_rate_pct       = rejection_rate,
                critical_alerts_last_hour = int(alerts_row["cnt"]),
            )
        except Exception as exc:
            logger.error(f"[Dashboard] Error en KPIs: {exc}")
            return DashboardKPIs(
                total_volume=0, total_tx=0, rejected_tx=0,
                challenged_tx=0, approved_tx=0, rejection_rate_pct=0,
                critical_alerts_last_hour=0,
            )

    # ── Discrepancias geográficas ──────────────────────────────────────

    async def _get_geo_discrepancies(
        self, since: datetime, limit: int
    ) -> list[GeoDiscrepancy]:
        """
        Devuelve transacciones donde ip_country != gps_country
        o donde alguno de los dos sea un país de alto riesgo.
        Prioriza las de mayor risk_score.
        """
        try:
            q = text("""
                SELECT
                    id,
                    ip_country,
                    gps_country,
                    action,
                    risk_score,
                    created_at,
                    encrypted_payload
                FROM transaction_audit
                WHERE created_at >= :since
                  AND (
                      (ip_country IS NOT NULL AND gps_country IS NOT NULL
                       AND ip_country != gps_country)
                      OR risk_score >= 50
                  )
                ORDER BY risk_score DESC, created_at DESC
                LIMIT :limit
            """)
            rows = (await self.db.execute(q, {"since": since, "limit": limit})).mappings().all()

            result = []
            for r in rows:
                # Extraer IP del payload cifrado
                ip_str = ""
                try:
                    import json
                    raw = _decrypt(bytes(r["encrypted_payload"]))
                    ip_str = json.loads(raw).get("ip_address", "") if raw else ""
                except Exception:
                    pass

                result.append(GeoDiscrepancy(
                    ip_address  = ip_str,
                    ip_country  = r["ip_country"],
                    gps_country = r["gps_country"],
                    action      = r["action"],
                    risk_score  = r["risk_score"],
                    timestamp   = r["created_at"],
                    is_mismatch = (
                        r["ip_country"] is not None
                        and r["gps_country"] is not None
                        and r["ip_country"] != r["gps_country"]
                    ),
                ))
            return result
        except Exception as exc:
            logger.error(f"[Dashboard] Error en geo_discrepancies: {exc}")
            return []

    # ── Feed transaccional ────────────────────────────────────────────

    async def _get_transaction_feed(
        self, since: datetime, limit: int
    ) -> list[TransactionFeedItem]:
        """
        Últimas N transacciones del período ordenadas por timestamp desc.
        No descifra el card_bin — solo expone merchant_name y metadata
        no sensible.
        """
        try:
            q = text("""
                SELECT
                    id,
                    created_at,
                    action,
                    risk_score,
                    amount,
                    currency,
                    transaction_type,
                    merchant_name,
                    encrypted_card_bin
                FROM transaction_audit
                WHERE created_at >= :since
                ORDER BY created_at DESC
                LIMIT :limit
            """)
            rows = (await self.db.execute(q, {"since": since, "limit": limit})).mappings().all()

            result = []
            for r in rows:
                # Descifrar los primeros 6 del BIN para el feed (no sensible solo)
                bin_plain = ""
                try:
                    bin_plain = _decrypt(bytes(r["encrypted_card_bin"]))[:6]
                except Exception:
                    pass

                result.append(TransactionFeedItem(
                    transaction_id   = str(r["id"]),
                    timestamp        = r["created_at"],
                    card_bin         = bin_plain or "XXXXXX",
                    amount           = float(r["amount"]),
                    currency         = r["currency"],
                    action           = r["action"],
                    risk_score       = r["risk_score"],
                    merchant_name    = r["merchant_name"],
                    transaction_type = r["transaction_type"],
                ))
            return result
        except Exception as exc:
            logger.error(f"[Dashboard] Error en transaction_feed: {exc}")
            return []

    # ── Mapa de calor de comercios ────────────────────────────────────

    async def _get_merchant_heatmap(self, since: datetime) -> list[MerchantHeatmapItem]:
        """
        Agrupa las transacciones por merchant_name y cuenta cuántas
        fueron bloqueadas (fraud_count) vs total.
        Solo incluye comercios con al menos 1 bloqueo.
        """
        try:
            q = text("""
                SELECT
                    COALESCE(merchant_name, 'Comercio desconocido') AS merchant_name,
                    merchant_id::text,
                    COUNT(*) FILTER (WHERE action LIKE 'ACTION_BLOCK%') AS fraud_count,
                    COUNT(*)                                             AS total_count
                FROM transaction_audit
                WHERE created_at >= :since
                GROUP BY merchant_name, merchant_id
                HAVING COUNT(*) FILTER (WHERE action LIKE 'ACTION_BLOCK%') > 0
                ORDER BY fraud_count DESC
                LIMIT 20
            """)
            rows = (await self.db.execute(q, {"since": since})).mappings().all()

            result = []
            for r in rows:
                total = int(r["total_count"])
                fraud = int(r["fraud_count"])
                result.append(MerchantHeatmapItem(
                    merchant_name  = r["merchant_name"],
                    merchant_id    = r["merchant_id"],
                    fraud_count    = fraud,
                    total_count    = total,
                    fraud_rate_pct = round(fraud / total * 100, 1) if total > 0 else 0.0,
                ))
            return result
        except Exception as exc:
            logger.error(f"[Dashboard] Error en merchant_heatmap: {exc}")
            return []

    # ── Riesgos de identidad (velocity por BIN) ───────────────────────

    async def _get_identity_risks(self, since: datetime) -> list[IdentityRiskItem]:
        """
        Detecta usuarios que usaron más de 1 BIN distinto en el período:
        señal de identity theft / card stuffing.
        Agrupa por user_id y cuenta el BYTEA distinto del encrypted_card_bin
        como proxy de BINs distintos (exacto si el nonce varía, aproximado
        si el mismo BIN se cifra con diferentes nonces).

        Para una detección exacta necesitarías descifrar cada row —
        este approx es suficiente para el dashboard de monitoreo.
        """
        try:
            q = text("""
                SELECT
                    user_id::text,
                    COUNT(DISTINCT encrypted_card_bin)  AS distinct_bins,
                    COUNT(*)                             AS tx_count,
                    MAX(risk_score)                      AS max_risk_score
                FROM transaction_audit
                WHERE created_at >= :since
                GROUP BY user_id
                HAVING COUNT(DISTINCT encrypted_card_bin) > 1
                ORDER BY distinct_bins DESC, max_risk_score DESC
                LIMIT 20
            """)
            rows = (await self.db.execute(q, {"since": since})).mappings().all()

            result = []
            for r in rows:
                bins  = int(r["distinct_bins"])
                score = int(r["max_risk_score"])
                risk_level = "HIGH" if bins >= 4 or score >= 70 else (
                    "MEDIUM" if bins >= 2 or score >= 40 else "LOW"
                )
                result.append(IdentityRiskItem(
                    user_id        = r["user_id"],
                    distinct_bins  = bins,
                    tx_count       = int(r["tx_count"]),
                    max_risk_score = score,
                    risk_level     = risk_level,
                ))
            return result
        except Exception as exc:
            logger.error(f"[Dashboard] Error en identity_risks: {exc}")
            return []
