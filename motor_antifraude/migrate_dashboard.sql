-- =======================================================================
-- Migración: Dashboard — Tabla merchants + columnas en transaction_audit
-- Aplicar manualmente en el contenedor Docker:
--   docker exec -it <postgres_container> psql -U <user> -d <db> -f migrate_dashboard.sql
-- =======================================================================

-- ── 1. Tabla de comercios (merchants) ────────────────────────────────

CREATE TABLE IF NOT EXISTS merchants (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(200) NOT NULL,
    ruc         VARCHAR(20)  UNIQUE,
    category    VARCHAR(50)  NOT NULL DEFAULT 'UNKNOWN',
    is_active   BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_merchants_name ON merchants (name);
CREATE INDEX IF NOT EXISTS idx_merchants_ruc  ON merchants (ruc);

-- ── 2. Nuevas columnas en transaction_audit ──────────────────────────

ALTER TABLE transaction_audit
    ADD COLUMN IF NOT EXISTS merchant_id   UUID        REFERENCES merchants(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS merchant_name VARCHAR(200),
    ADD COLUMN IF NOT EXISTS ip_country    CHAR(3),
    ADD COLUMN IF NOT EXISTS gps_country   CHAR(3);

CREATE INDEX IF NOT EXISTS idx_audit_merchant_id ON transaction_audit (merchant_id);
CREATE INDEX IF NOT EXISTS idx_audit_created_at  ON transaction_audit (created_at);

-- ── 3. Merchants de demo para pruebas ────────────────────────────────

INSERT INTO merchants (name, ruc, category) VALUES
    ('Maxiplus S.A.',    '1791234560001', 'ECOMMERCE'),
    ('Aki Tiendas',      '1790987650001', 'POS'),
    ('TuPrecio Online',  '1792345670001', 'ECOMMERCE'),
    ('FarmaExpress',     '1793456780001', 'POS'),
    ('Kiwi Market',      '1794567890001', 'ECOMMERCE')
ON CONFLICT (ruc) DO NOTHING;
