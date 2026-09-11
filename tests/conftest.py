# ==============================================================================
# MANDATORY TEST DATABASE ISOLATION
#
# Tests must NEVER touch the real Supabase database — a prior bug caused every
# test run to create real junk records in production. This isolation is mandatory.
# ==============================================================================

import os
import sys
import shutil
import socket
from pathlib import Path
import pytest

# Ensure repository root is on sys.path
root_dir = str(Path(__file__).resolve().parent.parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

# 1. FORCE SQLITE FALLBACK: Clear Supabase credentials before ANY src_py imports.
# In Pydantic Settings, environment variables override .env file entries.
# Overriding with empty strings ensures Settings() will not load production Supabase credentials.
os.environ["SUPABASE_URL"] = ""
os.environ["SUPABASE_SERVICE_ROLE_KEY"] = ""
os.environ["SUPABASE_KEY"] = ""

# 2. ISOLATE SQLITE DATABASE: Point db_path to a dedicated test path
# This guarantees tests never touch data/auth.db (local dev fallback) either.
test_data_dir = Path(root_dir) / "test_data"
test_db_path = str(test_data_dir / "test_auth.db")
os.environ["DB_PATH"] = test_db_path

# 3. Disable HTTPS requirement in tests
os.environ["REQUIRE_HTTPS"] = "false"

# 4. NETWORK GUARD: Prevent any outbound network calls to Supabase during test runs
_orig_getaddrinfo = socket.getaddrinfo

def _guarded_getaddrinfo(host, port, *args, **kwargs):
    if host and "supabase.co" in str(host):
        raise RuntimeError(
            f"CRITICAL SECURITY VIOLATION: Test attempted network connection to Supabase ({host})! "
            "Tests must run against local SQLite fallback only."
        )
    return _orig_getaddrinfo(host, port, *args, **kwargs)

socket.getaddrinfo = _guarded_getaddrinfo

# 5. Reset and enforce singleton settings & DB client instances
try:
    from src_py.config import settings
    settings.supabase_url = None
    settings.supabase_service_role_key = None
    settings.supabase_key = None
    settings.require_https = False
    settings.db_path = test_db_path

    from src_py.db import client as db_client
    db_client._supabase_client = None
    db_client._sqlite_fallback_conn = None
except Exception:
    pass


@pytest.fixture(scope="session", autouse=True)
def configure_test_environment():
    """Guarantees complete isolation from Supabase and persistent local databases."""
    from src_py.config import settings
    from src_py.db import client as db_client

    # Verify that Supabase is completely bypassed
    assert not settings.supabase_url, (
        f"CRITICAL ERROR: settings.supabase_url must be empty during tests, found: {settings.supabase_url}"
    )
    assert db_client.get_supabase_client() is None, (
        "CRITICAL ERROR: db_client.get_supabase_client() must return None during tests!"
    )
    assert settings.db_path == test_db_path, (
        f"CRITICAL ERROR: settings.db_path must be {test_db_path}, found: {settings.db_path}"
    )

    print(f"\n[Test Safety Verified] Supabase URL is empty: {settings.supabase_url!r}")
    print(f"[Test Safety Verified] Supabase client: {db_client.get_supabase_client()}")
    print(f"[Test Safety Verified] Isolated test database: {settings.db_path}")

    yield

    # Cleanup: close connection and purge isolated test database
    try:
        if db_client._sqlite_fallback_conn is not None:
            db_client._sqlite_fallback_conn.close()
            db_client._sqlite_fallback_conn = None
    except Exception:
        pass

    if test_data_dir.exists():
        try:
            shutil.rmtree(test_data_dir, ignore_errors=True)
        except Exception:
            pass
