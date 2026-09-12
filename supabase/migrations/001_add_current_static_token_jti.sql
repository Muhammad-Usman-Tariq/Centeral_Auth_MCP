-- ========================================================================
-- Migration: 001_add_current_static_token_jti.sql
-- Description: Add current_static_token_jti column to mcp_clients for
--              individual static token rotation tracking and invalidation.
-- ========================================================================

ALTER TABLE public.mcp_clients ADD COLUMN IF NOT EXISTS current_static_token_jti TEXT;
