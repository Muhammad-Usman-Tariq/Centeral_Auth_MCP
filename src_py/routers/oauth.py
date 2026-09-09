import base64
import urllib.parse
from fastapi import APIRouter, Request, Response, HTTPException, status, Query
from fastapi.responses import RedirectResponse, JSONResponse
from typing import Optional, Dict, Any, List
from pydantic import BaseModel
from src_py.db import models
from src_py.services import client_service, oauth_service
from src_py.middleware.rate_limiter import token_limiter, register_limiter, auth_limiter

router = APIRouter(tags=["OAuth 2.1"])


class RegisterRequest(BaseModel):
    client_name: Optional[str] = None
    name: Optional[str] = None
    redirect_uris: Optional[List[str]] = []
    audience: Optional[str] = None


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(req: Request, body: Optional[RegisterRequest] = None):
    """RFC 7591 Dynamic Client Registration."""
    client_ip = req.client.host if req.client else "unknown"
    register_limiter.check(client_ip)

    data = {}
    if body:
        data = body.model_dump()
    else:
        try:
            data = await req.json()
        except Exception:
            data = {}

    mcp_name = data.get("client_name") or data.get("name")
    if not mcp_name:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_client_metadata",
                "error_description": "client_name is required"
            }
        )

    client_audience = data.get("audience") or f"mcp-{mcp_name.lower().replace(' ', '-')}"
    redirect_uris = data.get("redirect_uris") or []
    if isinstance(redirect_uris, str):
        redirect_uris = [redirect_uris]

    try:
        reg_result = client_service.register_client(
            name=mcp_name,
            audience=client_audience,
            allowed_redirect_uris=redirect_uris,
            client_type="confidential",
            ip_address=client_ip
        )
        client = reg_result["client"]

        return {
            "client_id": client["client_id"],
            "client_secret": reg_result["clientSecret"],
            "client_name": client["name"],
            "audience": client["audience"],
            "redirect_uris": client.get("allowed_redirect_uris", []),
            "grant_types": ["authorization_code", "client_credentials"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post"
        }
    except ValueError as e:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_client_metadata",
                "error_description": str(e)
            }
        )


@router.get("/authorize")
async def authorize(
    req: Request,
    response_type: Optional[str] = Query(None),
    client_id: Optional[str] = Query(None),
    redirect_uri: Optional[str] = Query(None),
    scope: str = Query("mcp:all"),
    state: str = Query(""),
    code_challenge: Optional[str] = Query(None),
    code_challenge_method: Optional[str] = Query(None)
):
    """OAuth 2.1 /authorize endpoint enforcing PKCE with S256."""
    client_ip = req.client.host if req.client else "unknown"
    auth_limiter.check(client_ip)

    # 1. Validate response_type
    if response_type != "code":
        return JSONResponse(
            status_code=400,
            content={
                "error": "unsupported_response_type",
                "error_description": "Only response_type=code is supported in OAuth 2.1"
            }
        )

    # 2. Validate client_id
    if not client_id:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "error_description": "client_id is required"
            }
        )

    client = models.get_client_by_client_id(client_id)
    if not client:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_client",
                "error_description": "Unknown client_id"
            }
        )

    if client.get("revoked"):
        return JSONResponse(
            status_code=403,
            content={
                "error": "access_denied",
                "error_description": "This MCP client has been revoked"
            }
        )

    # 3. Validate redirect_uri
    if not redirect_uri:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "error_description": "redirect_uri is required"
            }
        )

    allowed_uris = client.get("allowed_redirect_uris") or []
    if allowed_uris:
        is_allowed = False
        for uri in allowed_uris:
            if uri == redirect_uri:
                is_allowed = True
                break
            if redirect_uri.startswith("http://127.0.0.1:") or redirect_uri.startswith("http://localhost:"):
                if uri.startswith("http://127.0.0.1") or uri.startswith("http://localhost"):
                    is_allowed = True
                    break
        if not is_allowed:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_request",
                    "error_description": "redirect_uri is not whitelisted for this client"
                }
            )

    # 4. Validate PKCE (Mandatory in OAuth 2.1)
    if not code_challenge:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "error_description": "code_challenge is required (PKCE is mandatory in OAuth 2.1)"
            }
        )

    if not code_challenge_method or code_challenge_method.upper() != "S256":
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "error_description": "code_challenge_method must be S256"
            }
        )

    try:
        auth_code = oauth_service.create_authorization_code(
            client_id=client["client_id"],
            audience=client["audience"],
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method="S256",
            scope=scope
        )

        # Construct redirect target URL
        parsed = urllib.parse.urlparse(redirect_uri)
        query_params = dict(urllib.parse.parse_qsl(parsed.query))
        query_params["code"] = auth_code
        if state:
            query_params["state"] = state

        new_query = urllib.parse.urlencode(query_params)
        redirect_target = urllib.parse.urlunparse(parsed._replace(query=new_query))

        return RedirectResponse(url=redirect_target, status_code=302)
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "error": "server_error",
                "error_description": str(e)
            }
        )


@router.post("/token")
async def token(req: Request, response: Response):
    """OAuth 2.1 /token endpoint for authorization_code (PKCE) and client_credentials."""
    client_ip = req.client.host if req.client else "unknown"
    token_limiter.check(client_ip)

    # Read body (JSON or Form)
    body_data: Dict[str, Any] = {}
    content_type = req.headers.get("content-type", "")

    if "application/json" in content_type:
        try:
            body_data = await req.json()
        except Exception:
            body_data = {}
    elif "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        form = await req.form()
        body_data = dict(form)
    else:
        try:
            body_data = await req.json()
        except Exception:
            form = await req.form()
            body_data = dict(form)

    grant_type = body_data.get("grant_type")
    code = body_data.get("code")
    redirect_uri = body_data.get("redirect_uri")
    code_verifier = body_data.get("code_verifier")
    client_id = body_data.get("client_id")
    client_secret = body_data.get("client_secret")
    scope = body_data.get("scope", "mcp:all")

    # Check Basic Auth header
    auth_header = req.headers.get("authorization")
    if auth_header:
        parts = auth_header.split()
        if len(parts) == 2 and parts[0].lower() == "basic":
            try:
                decoded = base64.b64decode(parts[1]).decode("utf-8")
                u, p = decoded.split(":", 1)
                if u: client_id = urllib.parse.unquote(u)
                if p: client_secret = urllib.parse.unquote(p)
            except Exception:
                pass

    if not grant_type:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "error_description": "grant_type parameter is required"
            }
        )

    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    # Grant 1: authorization_code (Mode 1 PKCE)
    if grant_type == "authorization_code":
        if not code:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "code is required"}
            )
        if not code_verifier:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "code_verifier is required for PKCE"}
            )
        if not client_id:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "client_id is required"}
            )

        try:
            result = oauth_service.exchange_authorization_code(
                code=code,
                client_id=client_id,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
                ip_address=client_ip
            )
            return result
        except ValueError as e:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_grant", "error_description": str(e)}
            )

    # Grant 2: client_credentials (Machine-to-Machine)
    if grant_type == "client_credentials":
        if not client_id or not client_secret:
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_client", "error_description": "client_id and client_secret are required"}
            )

        try:
            result = oauth_service.exchange_client_credentials(
                client_id=client_id,
                client_secret=client_secret,
                scope=scope,
                ip_address=client_ip
            )
            return result
        except ValueError as e:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_grant", "error_description": str(e)}
            )

    return JSONResponse(
        status_code=400,
        content={
            "error": "unsupported_grant_type",
            "error_description": f'Grant type "{grant_type}" is not supported.'
        }
    )


@router.post("/introspect")
async def introspect(req: Request):
    """RFC 7662 Token Introspection."""
    data = {}
    try:
        data = await req.json()
    except Exception:
        form = await req.form()
        data = dict(form)

    token_val = data.get("token")
    if not token_val:
        return {"active": False}

    client_ip = req.client.host if req.client else "unknown"
    return oauth_service.introspect_token(token_val, client_ip)


@router.get("/revocations")
def get_revocations(response: Response):
    """Returns active list of revoked clients for instantaneous local verification checks by MCP middleware."""
    response.headers["Cache-Control"] = "no-cache"
    revoked_ids = models.get_revoked_client_ids()
    import datetime
    return {
        "revoked_client_ids": revoked_ids,
        "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }
