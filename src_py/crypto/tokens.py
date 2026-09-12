import time
import uuid
import re
import secrets
import hashlib
import base64
import hmac
from typing import Dict, Any, Optional
import jwt
import bcrypt
from src_py.config import settings
from src_py.crypto.keys import get_private_key_pem, get_public_key_pem, get_key_id


def sign_mcp_token(
    client_id: str,
    audience: str,
    mode: str = "oauth2",
    expires_in_seconds: Optional[int] = None,
    custom_claims: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Signs an RS256 JWT for an MCP Client.
    Works identically for Mode 1 (OAuth 2.1) and Mode 2 (Static Token Fallback).
    """
    if expires_in_seconds is None:
        expires_in_seconds = settings.access_token_expiry

    private_key = get_private_key_pem()
    kid = get_key_id()
    jti = str(uuid.uuid4())
    now = int(time.time())

    payload = {
        "iss": settings.clean_issuer_url,
        "sub": client_id,
        "client_id": client_id,
        "aud": audience,
        "auth_mode": mode,
        "jti": jti,
        "iat": now,
        "exp": now + expires_in_seconds
    }

    if custom_claims:
        payload.update(custom_claims)

    headers = {
        "kid": kid,
        "alg": "RS256"
    }

    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers=headers
    )

    return {
        "token": token,
        "jti": jti,
        "expires_in": expires_in_seconds,
        "token_type": "Bearer"
    }


def sign_static_token(
    client_id: str,
    audience: str,
    days: Optional[int] = None
) -> Dict[str, Any]:
    """Signs a static long-lived token (Mode 2 fallback). Default 365 days, or 3650 (10 yrs) for no-expiry."""
    if days is None:
        days = settings.static_token_expiry_days
    elif days <= 0:
        days = 3650  # 10 years (effectively no-expiry)
    expires_in_seconds = days * 24 * 60 * 60

    return sign_mcp_token(
        client_id=client_id,
        audience=audience,
        mode="static_token",
        expires_in_seconds=expires_in_seconds,
        custom_claims={"token_type_hint": "static_long_lived"}
    )


def verify_mcp_token(token: str, expected_audience: Optional[str] = None) -> Dict[str, Any]:
    """Verifies an RS256 token using the public key."""
    public_key = get_public_key_pem()
    decode_kwargs = {
        "algorithms": ["RS256"],
        "issuer": settings.clean_issuer_url,
        "options": {"verify_aud": bool(expected_audience)}
    }
    if expected_audience:
        decode_kwargs["audience"] = expected_audience

    return jwt.decode(token, public_key, **decode_kwargs)


def sign_admin_token(username: str) -> str:
    """Signs an Admin Session JWT."""
    now = int(time.time())
    payload = {
        "sub": username,
        "role": "admin",
        "iat": now,
        "exp": now + (12 * 60 * 60)
    }
    return jwt.encode(payload, settings.admin_jwt_secret, algorithm="HS256")


def verify_admin_token(token: str) -> Dict[str, Any]:
    """Verifies an Admin Session JWT."""
    return jwt.decode(token, settings.admin_jwt_secret, algorithms=["HS256"])


def verify_pkce_challenge(code_verifier: str, code_challenge: str, method: str = "S256") -> bool:
    """
    Verifies OAuth 2.1 PKCE S256 Challenge.
    RFC 7636: BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) == code_challenge
    """
    if method != "S256":
        return False
    if not code_verifier or not code_challenge:
        return False

    computed_digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed_challenge = base64.urlsafe_b64encode(computed_digest).decode("ascii").rstrip("=")

    return hmac.compare_digest(computed_challenge, code_challenge)


def generate_client_id(name: str = "") -> str:
    sanitized = re.sub(r"[^a-z0-9]", "-", name.lower())
    sanitized = re.sub(r"-+", "-", sanitized)[:16].strip("-")
    rand = secrets.token_hex(8)
    return f"mcp_{sanitized}_{rand}" if sanitized else f"mcp_{rand}"


def generate_client_secret() -> str:
    return f"mcp_sec_{secrets.token_urlsafe(32)}"


def generate_auth_code() -> str:
    return f"ac_{secrets.token_urlsafe(24)}"


def hash_secret(secret: str) -> str:
    salt = bcrypt.gensalt(10)
    return bcrypt.hashpw(secret.encode("utf-8"), salt).decode("utf-8")


def verify_secret(secret: str, hashed: str) -> bool:
    if not secret or not hashed:
        return False
    try:
        return bcrypt.checkpw(secret.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False
