import time
from typing import Dict, Any, Optional
from src_py.config import settings
from src_py.db import models
from src_py.crypto.tokens import (
    generate_auth_code,
    verify_pkce_challenge,
    sign_mcp_token,
    verify_mcp_token
)
from src_py.services import client_service


def get_authorization_server_metadata() -> Dict[str, Any]:
    """RFC 8414 OAuth 2.0 / 2.1 Authorization Server Metadata."""
    base = settings.clean_issuer_url
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "registration_endpoint": f"{base}/register",
        "jwks_uri": f"{base}/.well-known/jwks.json",
        "introspection_endpoint": f"{base}/introspect",
        "revocation_endpoint": f"{base}/revocations",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "client_credentials"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["mcp:all", "mcp:read", "mcp:write"],
        "service_documentation": f"{base}/admin",
        "ui_locales_supported": ["en"]
    }


def get_protected_resource_metadata(resource: Optional[str] = None) -> Dict[str, Any]:
    """OAuth 2.1 Protected Resource Metadata (PRM)."""
    base = settings.clean_issuer_url
    return {
        "resource": resource or base,
        "authorization_servers": [base],
        "scopes_supported": ["mcp:all"],
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{base}/admin"
    }


def create_authorization_code(
    client_id: str,
    audience: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str = "S256",
    scope: str = "mcp:all"
) -> str:
    """Creates an authorization code for OAuth 2.1 PKCE."""
    if code_challenge_method != "S256":
        raise ValueError("OAuth 2.1 requires code_challenge_method to be S256")
    if not code_challenge:
        raise ValueError("OAuth 2.1 requires code_challenge (PKCE)")

    code = generate_auth_code()
    expires_at = int(time.time() * 1000) + (settings.auth_code_expiry_seconds * 1000)

    models.create_auth_code(
        code=code,
        client_id=client_id,
        audience=audience,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        scope=scope,
        expires_at=expires_at
    )

    return code


class ClientAuthenticationError(Exception):
    """Raised when client authentication fails (invalid client_secret or missing for confidential client)."""
    pass


def exchange_authorization_code(
    code: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str,
    client_secret: Optional[str] = None,
    ip_address: Optional[str] = None
) -> Dict[str, Any]:
    """Exchanges an authorization code for an RS256 access token with PKCE verification and client authentication."""
    # 1. Validate client identity
    client = models.get_client_by_client_id(client_id)
    if not client:
        models.add_token_event(
            event_type="failed",
            client_id=client_id,
            mode="oauth2_code",
            details="Unknown client_id",
            ip_address=ip_address
        )
        raise ClientAuthenticationError("Unknown client_id")

    if client.get("revoked"):
        models.add_token_event(
            event_type="failed",
            client_id=client_id,
            mode="oauth2_code",
            details="Client has been revoked",
            ip_address=ip_address
        )
        raise ValueError("Client has been revoked")

    # 2. Client authentication (when client_secret is provided)
    if client_secret is not None:
        if not client_service.authenticate_client(client_id, client_secret):
            models.add_token_event(
                event_type="failed",
                client_id=client_id,
                mode="oauth2_code",
                details="Client authentication failed (invalid client_secret)",
                ip_address=ip_address
            )
            raise ClientAuthenticationError("Client authentication failed")

    # 3. Retrieve and validate authorization code
    auth_code = models.get_auth_code(code)
    if not auth_code:
        models.add_token_event(
            event_type="failed",
            client_id=client_id,
            mode="oauth2_code",
            details="Invalid authorization code",
            ip_address=ip_address
        )
        raise ValueError("Invalid authorization code")

    if auth_code.get("used"):
        models.add_token_event(
            event_type="failed",
            client_id=client_id,
            mode="oauth2_code",
            details="Authorization code already used",
            ip_address=ip_address
        )
        raise ValueError("Authorization code has already been used")

    now_ms = int(time.time() * 1000)
    if now_ms > auth_code.get("expires_at", 0):
        models.add_token_event(
            event_type="failed",
            client_id=client_id,
            mode="oauth2_code",
            details="Authorization code expired",
            ip_address=ip_address
        )
        raise ValueError("Authorization code expired")

    if auth_code.get("client_id") != client_id:
        models.add_token_event(
            event_type="failed",
            client_id=client_id,
            mode="oauth2_code",
            details="Client ID mismatch for authorization code",
            ip_address=ip_address
        )
        raise ValueError("Client ID mismatch")

    if auth_code.get("redirect_uri") != redirect_uri:
        models.add_token_event(
            event_type="failed",
            client_id=client_id,
            mode="oauth2_code",
            details="Redirect URI mismatch",
            ip_address=ip_address
        )
        raise ValueError("Redirect URI mismatch")

    # 4. Verify PKCE S256
    if not verify_pkce_challenge(code_verifier, auth_code.get("code_challenge", ""), auth_code.get("code_challenge_method", "S256")):
        models.add_token_event(
            event_type="failed",
            client_id=client_id,
            mode="oauth2_code",
            details="PKCE code_verifier verification failed",
            ip_address=ip_address
        )
        raise ValueError("Invalid code_verifier for PKCE challenge")

    # 5. Mark code as used immediately (single-use enforcement)
    models.mark_auth_code_used(code)

    # Issue RS256 token
    scope = auth_code.get("scope", "mcp:all")
    token_res = sign_mcp_token(
        client_id=client["client_id"],
        audience=auth_code.get("audience") or client["audience"],
        mode="oauth2_code",
        expires_in_seconds=settings.access_token_expiry,
        custom_claims={"scope": scope}
    )

    models.add_token_event(
        event_type="issued",
        client_id=client["client_id"],
        audience=client["audience"],
        mode="oauth2_code",
        details={"jti": token_res["jti"], "scope": scope},
        ip_address=ip_address
    )

    return {
        "access_token": token_res["token"],
        "token_type": "Bearer",
        "expires_in": token_res["expires_in"],
        "scope": scope
    }


def exchange_client_credentials(
    client_id: str,
    client_secret: str,
    scope: str = "mcp:all",
    ip_address: Optional[str] = None
) -> Dict[str, Any]:
    """Client Credentials Grant (Machine-to-Machine)."""
    client = client_service.authenticate_client(client_id, client_secret)
    if not client:
        models.add_token_event(
            event_type="failed",
            client_id=client_id,
            mode="client_credentials",
            details="Invalid client credentials or client revoked",
            ip_address=ip_address
        )
        raise ValueError("Invalid client credentials or client revoked")

    token_res = sign_mcp_token(
        client_id=client["client_id"],
        audience=client["audience"],
        mode="client_credentials",
        expires_in_seconds=settings.access_token_expiry,
        custom_claims={"scope": scope}
    )

    models.add_token_event(
        event_type="issued",
        client_id=client["client_id"],
        audience=client["audience"],
        mode="client_credentials",
        details={"jti": token_res["jti"], "scope": scope},
        ip_address=ip_address
    )

    return {
        "access_token": token_res["token"],
        "token_type": "Bearer",
        "expires_in": token_res["expires_in"],
        "scope": scope
    }


def introspect_token(token: str, ip_address: Optional[str] = None) -> Dict[str, Any]:
    """RFC 7662 Token Introspection."""
    try:
        decoded = verify_mcp_token(token)
        client_id = decoded.get("sub") or decoded.get("client_id")

        client = models.get_client_by_client_id(client_id)
        if not client or client.get("revoked"):
            return {"active": False}

        jti = decoded.get("jti")
        if jti and models.is_token_jti_revoked(jti):
            return {"active": False}

        models.add_token_event(
            event_type="introspected",
            client_id=decoded.get("client_id"),
            audience=decoded.get("aud"),
            mode=decoded.get("auth_mode", "token"),
            details={"jti": jti, "active": True},
            ip_address=ip_address
        )

        return {
            "active": True,
            "client_id": decoded.get("client_id"),
            "sub": decoded.get("sub"),
            "aud": decoded.get("aud"),
            "iss": decoded.get("iss"),
            "exp": decoded.get("exp"),
            "iat": decoded.get("iat"),
            "jti": decoded.get("jti"),
            "auth_mode": decoded.get("auth_mode"),
            "token_type": "Bearer"
        }
    except Exception:
        return {"active": False}
