-- ========================================================================
-- Central Auth for MCP - Supabase (PostgreSQL) Schema
-- ========================================================================

-- Enable pgcrypto extension for gen_random_uuid if not already enabled
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. Table: mcp_clients
CREATE TABLE IF NOT EXISTS public.mcp_clients (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    name TEXT NOT NULL,
    client_id TEXT UNIQUE NOT NULL,
    client_secret_hash TEXT NOT NULL,
    audience TEXT UNIQUE NOT NULL,
    allowed_redirect_uris JSONB DEFAULT '[]'::jsonb,
    client_type TEXT DEFAULT 'confidential',
    revoked BOOLEAN DEFAULT false,
    current_static_token_jti TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mcp_clients_client_id ON public.mcp_clients(client_id);
CREATE INDEX IF NOT EXISTS idx_mcp_clients_audience ON public.mcp_clients(audience);

-- 2. Table: token_events (Audit Log)
CREATE TABLE IF NOT EXISTS public.token_events (
    id BIGSERIAL PRIMARY KEY,
    client_id TEXT,
    audience TEXT,
    event_type TEXT NOT NULL, -- 'issued', 'failed', 'revoked', 'introspected', 'registered'
    mode TEXT,                -- 'oauth2_code', 'client_credentials', 'static_token', 'admin'
    details TEXT,
    ip_address TEXT,
    timestamp TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_token_events_timestamp ON public.token_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_token_events_client_id ON public.token_events(client_id);

-- 3. Table: auth_codes (OAuth 2.1 PKCE authorization codes)
CREATE TABLE IF NOT EXISTS public.auth_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES public.mcp_clients(client_id) ON DELETE CASCADE,
    audience TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL DEFAULT 'S256',
    scope TEXT,
    expires_at BIGINT NOT NULL, -- Unix timestamp in milliseconds
    used BOOLEAN DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_auth_codes_client_id ON public.auth_codes(client_id);

-- 4. Table: revoked_tokens
CREATE TABLE IF NOT EXISTS public.revoked_tokens (
    jti TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    revoked_at TIMESTAMPTZ DEFAULT now()
);

-- 5. Table: admin_users
CREATE TABLE IF NOT EXISTS public.admin_users (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- ========================================================================
-- Row Level Security (RLS) Configuration
-- ========================================================================
-- Enable RLS on all tables
ALTER TABLE public.mcp_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.token_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.auth_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.revoked_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.admin_users ENABLE ROW LEVEL SECURITY;

-- Revoke all direct permissions from the 'anon' role
-- (All database interactions MUST flow through the backend via service_role key)
REVOKE ALL ON public.mcp_clients FROM anon;
REVOKE ALL ON public.token_events FROM anon;
REVOKE ALL ON public.auth_codes FROM anon;
REVOKE ALL ON public.revoked_tokens FROM anon;
REVOKE ALL ON public.admin_users FROM anon;

REVOKE ALL ON SEQUENCE public.token_events_id_seq FROM anon;

-- Grant permissions to authenticated service role
GRANT ALL ON ALL TABLES IN SCHEMA public TO service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO service_role;
