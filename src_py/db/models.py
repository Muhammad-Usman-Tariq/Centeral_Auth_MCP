import json
import uuid
import datetime
from typing import Dict, Any, List, Optional
import bcrypt
from src_py.config import settings
from src_py.db.client import get_supabase_client, get_sqlite_fallback


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def init_db():
    """Ensures tables and default admin account exist."""
    admin = get_admin_by_username(settings.admin_username)
    if not admin:
        salt = bcrypt.gensalt(10)
        password_hash = bcrypt.hashpw(settings.admin_password.encode("utf-8"), salt).decode("utf-8")
        create_admin_user(
            username=settings.admin_username,
            password_hash=password_hash
        )
        print(f"[Database] Initialized default admin user: {settings.admin_username}")


# ========================================================================
# MCP Clients
# ========================================================================

def create_client(
    id: str,
    name: str,
    client_id: str,
    client_secret_hash: str,
    audience: str,
    allowed_redirect_uris: List[str],
    client_type: str = "confidential"
) -> Dict[str, Any]:
    supabase = get_supabase_client()
    created_at = _now_iso()

    data = {
        "id": id,
        "name": name,
        "client_id": client_id,
        "client_secret_hash": client_secret_hash,
        "audience": audience,
        "allowed_redirect_uris": allowed_redirect_uris,
        "client_type": client_type,
        "revoked": False,
        "created_at": created_at
    }

    if supabase:
        supabase.table("mcp_clients").insert(data).execute()
        return get_client_by_client_id(client_id)

    # SQLite fallback
    conn = get_sqlite_fallback()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO mcp_clients 
            (id, name, client_id, client_secret_hash, audience, allowed_redirect_uris, client_type, revoked, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
    """, (
        id, name, client_id, client_secret_hash, audience,
        json.dumps(allowed_redirect_uris), client_type, created_at
    ))
    conn.commit()
    return get_client_by_client_id(client_id)


def _format_client(row: Dict[str, Any]) -> Dict[str, Any]:
    if not row:
        return None
    d = dict(row)
    d["revoked"] = bool(d.get("revoked", False))
    uris = d.get("allowed_redirect_uris", [])
    if isinstance(uris, str):
        try:
            d["allowed_redirect_uris"] = json.loads(uris)
        except Exception:
            d["allowed_redirect_uris"] = []
    elif not isinstance(uris, list):
        d["allowed_redirect_uris"] = []
    return d


def get_client_by_client_id(client_id: str) -> Optional[Dict[str, Any]]:
    supabase = get_supabase_client()
    if supabase:
        res = supabase.table("mcp_clients").select("*").eq("client_id", client_id).maybe_single().execute()
        return _format_client(res.data) if res and res.data else None

    conn = get_sqlite_fallback()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM mcp_clients WHERE client_id = ?", (client_id,))
    row = cursor.fetchone()
    return _format_client(dict(row)) if row else None


def get_client_by_id(id: str) -> Optional[Dict[str, Any]]:
    supabase = get_supabase_client()
    if supabase:
        res = supabase.table("mcp_clients").select("*").eq("id", id).maybe_single().execute()
        return _format_client(res.data) if res and res.data else None

    conn = get_sqlite_fallback()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM mcp_clients WHERE id = ?", (id,))
    row = cursor.fetchone()
    return _format_client(dict(row)) if row else None


def get_client_by_audience(audience: str) -> Optional[Dict[str, Any]]:
    supabase = get_supabase_client()
    if supabase:
        res = supabase.table("mcp_clients").select("*").eq("audience", audience).maybe_single().execute()
        return _format_client(res.data) if res and res.data else None

    conn = get_sqlite_fallback()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM mcp_clients WHERE audience = ?", (audience,))
    row = cursor.fetchone()
    return _format_client(dict(row)) if row else None


def list_clients() -> List[Dict[str, Any]]:
    supabase = get_supabase_client()
    if supabase:
        res = supabase.table("mcp_clients").select("id, name, client_id, audience, allowed_redirect_uris, client_type, revoked, created_at").order("created_at", desc=True).execute()
        return [_format_client(r) for r in (res.data or [])]

    conn = get_sqlite_fallback()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, client_id, audience, allowed_redirect_uris, client_type, revoked, created_at FROM mcp_clients ORDER BY created_at DESC")
    return [_format_client(dict(r)) for r in cursor.fetchall()]


def update_client_revocation(id: str, revoked: bool) -> Optional[Dict[str, Any]]:
    supabase = get_supabase_client()
    if supabase:
        supabase.table("mcp_clients").update({"revoked": revoked}).eq("id", id).execute()
        return get_client_by_id(id)

    conn = get_sqlite_fallback()
    cursor = conn.cursor()
    cursor.execute("UPDATE mcp_clients SET revoked = ? WHERE id = ?", (1 if revoked else 0, id))
    conn.commit()
    return get_client_by_id(id)


def get_revoked_client_ids() -> List[str]:
    supabase = get_supabase_client()
    if supabase:
        res = supabase.table("mcp_clients").select("client_id").eq("revoked", True).execute()
        return [r["client_id"] for r in (res.data or [])]

    conn = get_sqlite_fallback()
    cursor = conn.cursor()
    cursor.execute("SELECT client_id FROM mcp_clients WHERE revoked = 1")
    return [r[0] for r in cursor.fetchall()]


# ========================================================================
# Auth Codes (OAuth 2.1 PKCE)
# ========================================================================

def create_auth_code(
    code: str,
    client_id: str,
    audience: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str,
    scope: str,
    expires_at: int
):
    supabase = get_supabase_client()
    data = {
        "code": code,
        "client_id": client_id,
        "audience": audience,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "scope": scope,
        "expires_at": expires_at,
        "used": False
    }
    if supabase:
        supabase.table("auth_codes").insert(data).execute()
        return

    conn = get_sqlite_fallback()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO auth_codes 
            (code, client_id, audience, redirect_uri, code_challenge, code_challenge_method, scope, expires_at, used)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
    """, (code, client_id, audience, redirect_uri, code_challenge, code_challenge_method, scope, expires_at))
    conn.commit()


def get_auth_code(code: str) -> Optional[Dict[str, Any]]:
    supabase = get_supabase_client()
    if supabase:
        res = supabase.table("auth_codes").select("*").eq("code", code).maybe_single().execute()
        if not res or not res.data:
            return None
        d = dict(res.data)
        d["used"] = bool(d.get("used", False))
        return d

    conn = get_sqlite_fallback()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM auth_codes WHERE code = ?", (code,))
    row = cursor.fetchone()
    if not row:
        return None
    d = dict(row)
    d["used"] = bool(d.get("used", 0))
    return d


def mark_auth_code_used(code: str):
    supabase = get_supabase_client()
    if supabase:
        supabase.table("auth_codes").update({"used": True}).eq("code", code).execute()
        return

    conn = get_sqlite_fallback()
    cursor = conn.cursor()
    cursor.execute("UPDATE auth_codes SET used = 1 WHERE code = ?", (code,))
    conn.commit()


# ========================================================================
# Revoked Tokens
# ========================================================================

def revoke_token_jti(jti: str, client_id: str):
    supabase = get_supabase_client()
    data = {
        "jti": jti,
        "client_id": client_id,
        "revoked_at": _now_iso()
    }
    if supabase:
        supabase.table("revoked_tokens").upsert(data).execute()
        return

    conn = get_sqlite_fallback()
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO revoked_tokens (jti, client_id, revoked_at) VALUES (?, ?, ?)",
                   (jti, client_id, _now_iso()))
    conn.commit()


def is_token_jti_revoked(jti: str) -> bool:
    supabase = get_supabase_client()
    if supabase:
        res = supabase.table("revoked_tokens").select("jti").eq("jti", jti).maybe_single().execute()
        return bool(res and res.data)

    conn = get_sqlite_fallback()
    cursor = conn.cursor()
    cursor.execute("SELECT jti FROM revoked_tokens WHERE jti = ?", (jti,))
    return bool(cursor.fetchone())


# ========================================================================
# Token Events (Audit Log)
# ========================================================================

def add_token_event(
    event_type: str,
    client_id: Optional[str] = None,
    audience: Optional[str] = None,
    mode: Optional[str] = None,
    details: Any = None,
    ip_address: Optional[str] = None
):
    details_str = json.dumps(details) if isinstance(details, (dict, list)) else (str(details) if details else None)
    timestamp = _now_iso()

    supabase = get_supabase_client()
    if supabase:
        supabase.table("token_events").insert({
            "client_id": client_id,
            "audience": audience,
            "event_type": event_type,
            "mode": mode,
            "details": details_str,
            "ip_address": ip_address,
            "timestamp": timestamp
        }).execute()
        return

    conn = get_sqlite_fallback()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO token_events 
            (client_id, audience, event_type, mode, details, ip_address, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (client_id, audience, event_type, mode, details_str, ip_address, timestamp))
    conn.commit()


def get_recent_events(limit: int = 50) -> List[Dict[str, Any]]:
    supabase = get_supabase_client()
    if supabase:
        res = supabase.table("token_events").select("*").order("id", desc=True).limit(limit).execute()
        return res.data or []

    conn = get_sqlite_fallback()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM token_events ORDER BY id DESC LIMIT ?", (limit,))
    return [dict(r) for r in cursor.fetchall()]


# ========================================================================
# Admin Users
# ========================================================================

def create_admin_user(username: str, password_hash: str) -> Dict[str, Any]:
    admin_id = str(uuid.uuid4())
    created_at = _now_iso()
    data = {
        "id": admin_id,
        "username": username,
        "password_hash": password_hash,
        "created_at": created_at
    }
    supabase = get_supabase_client()
    if supabase:
        supabase.table("admin_users").insert(data).execute()
        return data

    conn = get_sqlite_fallback()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO admin_users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                   (admin_id, username, password_hash, created_at))
    conn.commit()
    return data


def get_admin_by_username(username: str) -> Optional[Dict[str, Any]]:
    supabase = get_supabase_client()
    if supabase:
        res = supabase.table("admin_users").select("*").eq("username", username).maybe_single().execute()
        return res.data if res and res.data else None

    conn = get_sqlite_fallback()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin_users WHERE username = ?", (username,))
    row = cursor.fetchone()
    return dict(row) if row else None