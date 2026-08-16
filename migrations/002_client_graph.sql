ALTER TABLE observations
    ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'local',
    ADD COLUMN IF NOT EXISTS client_id UUID,
    ADD COLUMN IF NOT EXISTS resolution JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS observations_tenant_created_idx
    ON observations (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS observations_tenant_client_idx
    ON observations (tenant_id, client_id, created_at DESC);

CREATE TABLE IF NOT EXISTS clients (
    tenant_id TEXT NOT NULL,
    client_id UUID NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    observation_count BIGINT NOT NULL DEFAULT 1,
    latest_profile JSONB NOT NULL DEFAULT '{}'::jsonb,
    latest_fingerprints JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, client_id)
);

CREATE INDEX IF NOT EXISTS clients_tenant_last_seen_idx
    ON clients (tenant_id, last_seen DESC);
