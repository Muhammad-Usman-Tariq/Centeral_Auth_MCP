import uuid
from typing import Dict, Any, List, Optional
from src_py.config import settings
from src_py.db import models
from src_py.crypto.tokens import (
    generate_client_id,
    generate_client_secret,
    hash_secret,
    verify_secret,
    sign_static_token
)


def register_client(
    name: str,
    audience: str,
    allowed_redirect_uris: Optional[List[str]] = None,
    client_type: str = "confidential",
    ip_address: Optional[str] = None
) -> Dict[str, Any]:
    """Registers a new MCP client via Admin UI or RFC 7591 Dynamic Client Registration."""
    if not name or not audience:
        raise ValueError("Both name and audience are required")

    clean_audience = audience.strip()
    existing = models.get_client_by_audience(clean_audience)
    if existing:
        raise ValueError(f'An MCP client with audience "{clean_audience}" already exists')

    client_id = generate_client_id(name)
    raw_secret = generate_client_secret()
    secret_hash = hash_secret(raw_secret)
    client_uuid = str(uuid.uuid4())
    redirect_uris = allowed_redirect_uris or []

    client = models.create_client(
        id=client_uuid,
        name=name.strip(),
        client_id=client_id,
        client_secret_hash=secret_hash,
        audience=clean_audience,
        allowed_redirect_uris=redirect_uris,
        client_type=client_type
    )

    models.add_token_event(
        event_type="registered",
        client_id=client_id,
        audience=clean_audience,
        mode="admin_or_dcr",
        details={"name": client["name"], "clientType": client_type},
        ip_address=ip_address
    )

    return {
        "client": client,
        "clientSecret": raw_secret  # Revealed ONCE to caller
    }


def generate_static_token_for_client(
    client_id: str,
    days: Optional[int] = None,
    ip_address: Optional[str] = None
) -> Dict[str, Any]:
    """Generates a Mode 2 static long-lived token for an MCP client."""
    client = models.get_client_by_client_id(client_id)
    if not client:
        raise ValueError("Client not found")
    if client.get("revoked"):
        raise ValueError("Cannot issue token for a revoked client")

    token_data = sign_static_token(
        client_id=client["client_id"],
        audience=client["audience"],
        days=days
    )

    models.add_token_event(
        event_type="issued",
        client_id=client["client_id"],
        audience=client["audience"],
        mode="static_token",
        details={"jti": token_data["jti"], "days": days, "expiresIn": token_data["expires_in"]},
        ip_address=ip_address
    )

    return {
        "token": token_data["token"],
        "jti": token_data["jti"],
        "expiresIn": token_data["expires_in"],
        "audience": client["audience"],
        "clientId": client["client_id"],
        "tokenType": "Bearer"
    }


def authenticate_client(client_id: str, client_secret: str) -> Optional[Dict[str, Any]]:
    """Authenticates client credentials."""
    client = models.get_client_by_client_id(client_id)
    if not client or client.get("revoked"):
        return None

    if not verify_secret(client_secret, client.get("client_secret_hash", "")):
        return None

    return client


def revoke_client(client_id_or_id: str, ip_address: Optional[str] = None) -> Dict[str, Any]:
    """Revokes an MCP client immediately."""
    client = models.get_client_by_id(client_id_or_id) or models.get_client_by_client_id(client_id_or_id)
    if not client:
        raise ValueError("Client not found")

    updated = models.update_client_revocation(client["id"], True)

    models.add_token_event(
        event_type="revoked",
        client_id=client["client_id"],
        audience=client["audience"],
        mode="admin",
        details={"action": "revoke_client"},
        ip_address=ip_address
    )

    return updated


def unrevoke_client(client_id_or_id: str, ip_address: Optional[str] = None) -> Dict[str, Any]:
    """Restores/unrevokes an MCP client."""
    client = models.get_client_by_id(client_id_or_id) or models.get_client_by_client_id(client_id_or_id)
    if not client:
        raise ValueError("Client not found")

    updated = models.update_client_revocation(client["id"], False)

    models.add_token_event(
        event_type="restored",
        client_id=client["client_id"],
        audience=client["audience"],
        mode="admin",
        details={"action": "unrevoke_client"},
        ip_address=ip_address
    )

    return updated
