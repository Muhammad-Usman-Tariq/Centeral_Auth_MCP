#!/usr/bin/env python3
"""
Data Migration Script: SQLite -> Supabase (PostgreSQL)

Exports existing records from the local SQLite database (`data/auth.db`)
and imports them into Supabase tables via the official `supabase-py` client.

Usage:
    export SUPABASE_URL="https://your-project.supabase.co"
    export SUPABASE_SERVICE_ROLE_KEY="your-service-role-key"
    python scripts/migrate_sqlite_to_supabase.py [--sqlite-path ./data/auth.db]
"""

import os
import sys
import json
import sqlite3
import argparse
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

try:
    from supabase import create_client, Client
except ImportError:
    print("[Error] `supabase` package is required. Run: pip install supabase")
    sys.exit(1)


def migrate(sqlite_path: str, supabase_url: str, supabase_key: str):
    if not os.path.exists(sqlite_path):
        print(f"[Info] SQLite database not found at {sqlite_path}. Nothing to migrate.")
        return

    print(f"[Migration] Connecting to SQLite at: {sqlite_path}")
    conn = sqlite3.connect(sqlite_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    print(f"[Migration] Connecting to Supabase at: {supabase_url}")
    supabase: Client = create_client(supabase_url, supabase_key)

    # 1. Migrate Admin Users
    try:
        cursor.execute("SELECT id, username, password_hash, created_at FROM admin_users")
        admin_rows = [dict(row) for row in cursor.fetchall()]
        if admin_rows:
            print(f"[Migration] Migrating {len(admin_rows)} admin user(s)...")
            supabase.table("admin_users").upsert(admin_rows).execute()
            print(f"[Migration] ✔ Admin users migrated successfully.")
    except sqlite3.OperationalError as e:
        print(f"[Warning] admin_users table skipped: {e}")

    # 2. Migrate MCP Clients
    try:
        cursor.execute("SELECT id, name, client_id, client_secret_hash, audience, allowed_redirect_uris, client_type, revoked, created_at FROM mcp_clients")
        client_rows = []
        for row in cursor.fetchall():
            d = dict(row)
            d["revoked"] = bool(d.get("revoked", 0))
            if isinstance(d.get("allowed_redirect_uris"), str):
                try:
                    d["allowed_redirect_uris"] = json.loads(d["allowed_redirect_uris"])
                except Exception:
                    d["allowed_redirect_uris"] = []
            client_rows.append(d)

        if client_rows:
            print(f"[Migration] Migrating {len(client_rows)} MCP client(s)...")
            supabase.table("mcp_clients").upsert(client_rows).execute()
            print(f"[Migration] ✔ MCP clients migrated successfully.")
    except sqlite3.OperationalError as e:
        print(f"[Warning] mcp_clients table skipped: {e}")

    # 3. Migrate Token Events (Audit Log)
    try:
        cursor.execute("SELECT id, client_id, audience, event_type, mode, details, ip_address, timestamp FROM token_events")
        event_rows = [dict(row) for row in cursor.fetchall()]
        if event_rows:
            print(f"[Migration] Migrating {len(event_rows)} audit event(s)...")
            # Batch in chunks of 100
            for i in range(0, len(event_rows), 100):
                chunk = event_rows[i:i + 100]
                supabase.table("token_events").upsert(chunk).execute()
            print(f"[Migration] ✔ Token events migrated successfully.")
    except sqlite3.OperationalError as e:
        print(f"[Warning] token_events table skipped: {e}")

    # 4. Migrate Revoked Tokens
    try:
        cursor.execute("SELECT jti, client_id, revoked_at FROM revoked_tokens")
        revoked_rows = [dict(row) for row in cursor.fetchall()]
        if revoked_rows:
            print(f"[Migration] Migrating {len(revoked_rows)} revoked token(s)...")
            supabase.table("revoked_tokens").upsert(revoked_rows).execute()
            print(f"[Migration] ✔ Revoked tokens migrated successfully.")
    except sqlite3.OperationalError as e:
        print(f"[Warning] revoked_tokens table skipped: {e}")

    conn.close()
    print("\n[Migration] =========================================")
    print("[Migration] SQLite to Supabase migration completed!")
    print("[Migration] =========================================\n")


def main():
    parser = argparse.ArgumentParser(description="Migrate Central Auth SQLite data to Supabase")
    parser.add_argument("--sqlite-path", default=os.getenv("DB_PATH", "./data/auth.db"), help="Path to SQLite DB")
    parser.add_argument("--supabase-url", default=os.getenv("SUPABASE_URL"), help="Supabase Project URL")
    parser.add_argument("--supabase-key", default=os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY"), help="Supabase Service Role Key")
    args = parser.parse_args()

    if not args.supabase_url or not args.supabase_key:
        print("[Error] SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY environment variables are required.")
        print("Example: python scripts/migrate_sqlite_to_supabase.py --supabase-url https://xyz.supabase.co --supabase-key eyJhbGci...")
        sys.exit(1)

    migrate(args.sqlite_path, args.supabase_url, args.supabase_key)


if __name__ == "__main__":
    main()
