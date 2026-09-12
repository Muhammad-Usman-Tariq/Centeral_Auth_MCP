import re
import secrets
from fastapi import APIRouter, Request, Depends, HTTPException, status, Query
from fastapi.responses import JSONResponse
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, AliasChoices
import bcrypt
from src_py.config import settings
from src_py.db import models
from src_py.services import client_service
from src_py.crypto.tokens import sign_admin_token
from src_py.middleware.admin_auth import get_current_admin
from src_py.middleware.rate_limiter import admin_login_limiter

router = APIRouter(prefix="/admin", tags=["Admin API"])


class AdminLoginRequest(BaseModel):
    username: str
    password: str


class CreateClientRequest(BaseModel):
    name: str
    audience: Optional[str] = None
    allowedRedirectUris: Optional[List[str]] = Field(
        default=None,
        validation_alias=AliasChoices("allowedRedirectUris", "allowed_redirect_uris", "redirect_uris")
    )
    generateStaticToken: bool = Field(
        default=True,
        validation_alias=AliasChoices("generateStaticToken", "generate_static_token")
    )
    staticTokenDays: int = Field(
        default=365,
        validation_alias=AliasChoices("staticTokenDays", "static_token_days")
    )


class StaticTokenRequest(BaseModel):
    days: int = 365


@router.post("/login")
async def admin_login(req: Request, body: AdminLoginRequest):
    """Admin Login endpoint."""
    client_ip = req.client.host if req.client else "unknown"
    admin_login_limiter.check(client_ip)

    username = body.username.strip()
    password = body.password

    if not username or not password:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "Username and password are required"}
        )

    admin = models.get_admin_by_username(username)
    if not admin:
        return JSONResponse(
            status_code=401,
            content={"success": False, "message": "Invalid username or password"}
        )

    valid = bcrypt.checkpw(password.encode("utf-8"), admin["password_hash"].encode("utf-8"))
    if not valid:
        return JSONResponse(
            status_code=401,
            content={"success": False, "message": "Invalid username or password"}
        )

    token = sign_admin_token(admin["username"])

    models.add_token_event(
        event_type="admin_login",
        client_id="admin",
        audience="admin-dashboard",
        mode="admin",
        details={"username": admin["username"]},
        ip_address=client_ip
    )

    return {
        "success": True,
        "token": token,
        "user": {
            "id": admin["id"],
            "username": admin["username"]
        }
    }


@router.get("/api/stats")
async def get_stats(admin: Dict[str, Any] = Depends(get_current_admin)):
    """Dashboard summary statistics."""
    clients = models.list_clients()
    recent_events = models.get_recent_events(100)

    total_clients = len(clients)
    active_clients = len([c for c in clients if not c.get("revoked")])
    revoked_clients = len([c for c in clients if c.get("revoked")])
    total_events = len(recent_events)

    return {
        "success": True,
        "stats": {
            "totalClients": total_clients,
            "activeClients": active_clients,
            "revokedClients": revoked_clients,
            "totalEvents": total_events
        }
    }


@router.get("/api/clients")
async def get_clients(admin: Dict[str, Any] = Depends(get_current_admin)):
    """List all registered MCP clients."""
    clients = models.list_clients()
    return {
        "success": True,
        "clients": clients
    }


@router.post("/api/clients", status_code=status.HTTP_201_CREATED)
async def create_mcp_client(
    req: Request,
    body: CreateClientRequest,
    admin: Dict[str, Any] = Depends(get_current_admin)
):
    """Register a new MCP client via Admin panel."""
    client_ip = req.client.host if req.client else "unknown"

    if not body.name or not body.name.strip():
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "MCP name is required"}
        )

    # 1. Determine audience: auto-generate if omitted/empty
    if body.audience and body.audience.strip():
        audience = body.audience.strip()
    else:
        # Auto-generate: lowercase, replace spaces/special characters with hyphens,
        # prefix with "mcp-", and append a short random suffix (4 hex characters)
        # Example: name="Invoicing MCP" -> audience="mcp-invoicing-a8f3"
        sanitized = re.sub(r"[^a-z0-9]+", "-", body.name.lower()).strip("-")
        sanitized = re.sub(r"^mcp-", "", sanitized)
        sanitized = re.sub(r"-mcp$", "", sanitized).strip("-")
        if not sanitized:
            sanitized = "server"
        for _ in range(5):
            rand_suffix = secrets.token_hex(2)
            candidate_audience = f"mcp-{sanitized}-{rand_suffix}"
            if not models.get_client_by_audience(candidate_audience):
                audience = candidate_audience
                break
        else:
            audience = f"mcp-{sanitized}-{secrets.token_hex(3)}"

    # 2. Determine redirect URIs: default to local/dev OAuth testing defaults if omitted
    redirect_uris = body.allowedRedirectUris
    if not redirect_uris:
        redirect_uris = ["http://127.0.0.1:*", "http://localhost:*"]

    try:
        reg_result = client_service.register_client(
            name=body.name.strip(),
            audience=audience,
            allowed_redirect_uris=redirect_uris,
            client_type="confidential",
            ip_address=client_ip
        )
        client = reg_result["client"]

        # 3. Always auto-generate Mode 2 static token on creation (default 365 days / 1 year)
        if body.staticTokenDays is not None:
            static_token_days = 3650 if body.staticTokenDays <= 0 else body.staticTokenDays
        else:
            static_token_days = 365
        static_token_data = client_service.generate_static_token_for_client(
            client_id=client["client_id"],
            days=static_token_days,
            ip_address=client_ip
        )

        # 4. Computed ready-to-paste .env snippet
        env_snippet = (
            f"JWKS_URI={settings.clean_issuer_url}/.well-known/jwks.json\n"
            f"MCP_AUDIENCE={client['audience']}\n"
            f"MCP_AUTH_TOKEN={static_token_data['token']}"
        )

        return {
            "success": True,
            "client": client,
            "clientSecret": reg_result["clientSecret"],  # Revealed ONCE
            "staticToken": static_token_data,
            "envSnippet": env_snippet
        }
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": str(e)}
        )


@router.post("/api/clients/{client_id_or_id}/revoke")
async def revoke_mcp_client(
    client_id_or_id: str,
    req: Request,
    admin: Dict[str, Any] = Depends(get_current_admin)
):
    """Revoke an MCP client immediately."""
    client_ip = req.client.host if req.client else "unknown"
    try:
        client = client_service.revoke_client(client_id_or_id, ip_address=client_ip)
        return {"success": True, "client": client}
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": str(e)}
        )


@router.post("/api/clients/{client_id_or_id}/unrevoke")
async def unrevoke_mcp_client(
    client_id_or_id: str,
    req: Request,
    admin: Dict[str, Any] = Depends(get_current_admin)
):
    """Restore / unrevoke an MCP client."""
    client_ip = req.client.host if req.client else "unknown"
    try:
        client = client_service.unrevoke_client(client_id_or_id, ip_address=client_ip)
        return {"success": True, "client": client}
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": str(e)}
        )


@router.post("/api/clients/{client_id_or_id}/static-token")
async def generate_client_static_token(
    client_id_or_id: str,
    req: Request,
    body: Optional[StaticTokenRequest] = None,
    admin: Dict[str, Any] = Depends(get_current_admin)
):
    """Generate a new Mode 2 static token for an MCP client."""
    client_ip = req.client.host if req.client else "unknown"
    if body and body.days is not None:
        days = 3650 if body.days <= 0 else body.days
    else:
        days = 365

    client = models.get_client_by_id(client_id_or_id) or models.get_client_by_client_id(client_id_or_id)
    if not client:
        return JSONResponse(
            status_code=404,
            content={"success": False, "message": "Client not found"}
        )

    try:
        static_token = client_service.generate_static_token_for_client(
            client_id=client["client_id"],
            days=days,
            ip_address=client_ip
        )
        return {"success": True, "staticToken": static_token}
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": str(e)}
        )


@router.get("/api/audit")
async def get_audit_log(
    limit: int = Query(50, le=200),
    admin: Dict[str, Any] = Depends(get_current_admin)
):
    """Retrieve recent token events for audit log."""
    events = models.get_recent_events(limit)
    return {
        "success": True,
        "events": events
    }
