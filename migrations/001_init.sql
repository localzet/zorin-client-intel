CREATE TABLE IF NOT EXISTS observations (
    id UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_ip INET,
    user_agent TEXT,
    http_version TEXT,
    tls JSONB NOT NULL DEFAULT '{}'::jsonb,
    http JSONB NOT NULL DEFAULT '{}'::jsonb,
    browser JSONB,
    fingerprints JSONB NOT NULL DEFAULT '{}'::jsonb,
    profile JSONB NOT NULL DEFAULT '{}'::jsonb,
    raw JSONB NOT NULL DEFAULT '{}'::jsonb,
    document JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS observations_created_at_idx
    ON observations (created_at DESC);

CREATE INDEX IF NOT EXISTS observations_source_ip_idx
    ON observations (source_ip);

CREATE INDEX IF NOT EXISTS observations_fingerprints_gin_idx
    ON observations USING GIN (fingerprints);

CREATE INDEX IF NOT EXISTS observations_profile_gin_idx
    ON observations USING GIN (profile);
