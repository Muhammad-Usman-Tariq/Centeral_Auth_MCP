from fastapi import APIRouter, Response, Query
from typing import Optional
from src_py.crypto.keys import get_jwks
from src_py.services import oauth_service

router = APIRouter(prefix="/.well-known", tags=["Discovery & Keys"])


@router.get("/oauth-authorization-server")
def get_oauth_authorization_server(response: Response):
    """RFC 8414 OAuth 2.0 / 2.1 Authorization Server Metadata."""
    response.headers["Cache-Control"] = "public, max-age=3600"
    return oauth_service.get_authorization_server_metadata()


@router.get("/oauth-protected-resource")
def get_oauth_protected_resource(response: Response, resource: Optional[str] = Query(None)):
    """OAuth 2.1 Protected Resource Metadata (PRM)."""
    response.headers["Cache-Control"] = "public, max-age=3600"
    return oauth_service.get_protected_resource_metadata(resource)


@router.get("/jwks.json")
def get_jwks_json(response: Response):
    """RFC 7517 JSON Web Key Set (JWKS) containing the public RS256 key(s)."""
    response.headers["Cache-Control"] = "public, max-age=300"
    return get_jwks()
