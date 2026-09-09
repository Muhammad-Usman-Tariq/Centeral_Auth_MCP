import os
import sqlite3
import json
from typing import Optional, Any, Dict, List
from src_py.config import settings

_supabase_client = None
_sqlite_fallback_conn = None


def get_supabase_client():
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client

    if settings.supabase_url and settings.effective_supabase_key:
        try:
            from supabase import create_client, Client
            _supabase_client = create_client(
                settings.supabase_url,
                settings.effective_supabase_key
            )
            print(f"[Database] Connected to Supabase at: {settings.supabase_url}")
            return _supabase_client
        except Exception as e:
            print(f"[Database Warning] Failed to initialize Supabase client: {e}")

    return None


def get_sqlite_fallback():
    """Provides local SQLite fallback engine when Supabase credentials are not configured."""
    global _sqlite_fallback_conn
    if _sqlite_fallback_conn is not None:
        return _sqlite_fallback_conn

    db_path = settings.db_path
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS mcp_clients (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            client_id TEXT UNIQUE NOT NULL,
            client_secret_hash TEXT NOT NULL,
            audience TEXT UNIQUE NOT NULL,
            allowed_redirect_uris TEXT DEFAULT '[]',
            client_type TEXT DEFAULT 'confidential',
            revoked INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_mcp_clients_client_id ON mcp_clients(client_id);
        CREATE INDEX IF NOT EXISTS idx_mcp_clients_audience ON mcp_clients(audience);

        CREATE TABLE IF NOT EXISTS token_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT,
            audience TEXT,
            event_type TEXT NOT NULL,
            mode TEXT,
            details TEXT,
            ip_address TEXT,
            timestamp TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_token_events_timestamp ON token_events(timestamp DESC);

        CREATE TABLE IF NOT EXISTS auth_codes (
            code TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            audience TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            code_challenge TEXT NOT NULL,
            code_challenge_method TEXT NOT NULL,
            scope TEXT,
            expires_at INTEGER NOT NULL,
            used INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS revoked_tokens (
            jti TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            revoked_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS admin_users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
    """)
    conn.commit()
    _sqlite_fallback_conn = conn
    return _sqlite_fallback_conn
