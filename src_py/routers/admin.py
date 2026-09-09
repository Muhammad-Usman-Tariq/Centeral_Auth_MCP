from fastapi import APIRouter, Request, Depends, HTTPException, status, Query
from fastapi.responses import JSONResponse
from typing import Optional, Dict, Any, List
from pydantic import BaseModel
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
    audience: str
    allowedRedirectUris: Optional[List[str]] = []
    generateStaticToken: bool = True
    staticTokenDays: int = 90


class StaticTokenRequest(BaseModel):
    days: int = 90


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

    if not body.name or not body.audience:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "MCP name and audience are required"}
        )

    try:
        reg_result = client_service.register_client(
            name=body.name,
            audience=body.audience,
            allowed_redirect_uris=body.allowedRedirectUris,
            client_type="confidential",
            ip_address=client_ip
        )
        client = reg_result["client"]

        static_token_data = None
        if body.generateStaticToken:
            static_token_data = client_service.generate_static_token_for_client(
                client_id=client["client_id"],
                days=body.staticTokenDays,
                ip_address=client_ip
            )

        return {
            "success": True,
            "client": client,
            "clientSecret": reg_result["clientSecret"],  # Revealed ONCE
            "staticToken": static_token_data
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
    days = body.days if body else 90

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
