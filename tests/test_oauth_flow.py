"""
Comprehensive Integration Test Suite for OAuth 2.1 Dynamic Flow in Central Auth MCP.
Exercises end-to-end:
  1. RFC 7591 Dynamic Client Registration (/register)
  2. RFC 7636 PKCE S256 code_verifier / code_challenge generation
  3. OAuth 2.1 Authorization Request (/authorize) with 302 redirect & code extraction
  4. Token Exchange (/token) with authorization_code & PKCE verifier
  5. RS256 signature and claims verification against RFC 7517 JWKS (/.well-known/jwks.json)
  6. Explicit failure cases:
     - Wrong code_verifier (PKCE mismatch -> 400 invalid_grant)
     - Already-used authorization code (Replay -> 400 invalid_grant)
     - Expired authorization code (Expired -> 400 invalid_grant)
     - Wrong client_secret (Invalid client -> 401 invalid_client)
     - Unwhitelisted redirect_uri (/authorize -> 400 invalid_request)
"""

import sys
import time
import base64
import hashlib
import secrets
import urllib.parse
from pathlib import Path

import jwt
import pytest
from fastapi.testclient import TestClient

# Ensure root directory is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src_py.main import app
from src_py.config import settings
from src_py.crypto.keys import init_keys
from src_py.db.models import init_db, create_auth_code


@pytest.fixture(scope="module")
def client():
    """Initializes keys, database and provides FastAPI TestClient."""
    init_keys()
    init_db()
    with TestClient(app) as test_client:
        yield test_client


def generate_pkce_pair():
    """Generates an RFC 7636 compliant code_verifier and S256 code_challenge."""
    # Verifier: 43-128 characters from unreserved characters set
    code_verifier = secrets.token_urlsafe(64)
    # Challenge: BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) without padding
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return code_verifier, code_challenge


def test_full_oauth21_dynamic_flow(client: TestClient):
    """
    Simulates a full end-to-end OAuth 2.1 compliant MCP client:
    DCR -> PKCE S256 -> /authorize -> /token -> JWKS signature verification.
    """
    # -------------------------------------------------------------------------
    # a. Dynamic Client Registration (RFC 7591)
    # -------------------------------------------------------------------------
    redirect_uri = "http://localhost:8080/mcp/callback"
    client_name = f"Test Dynamic MCP Client {secrets.token_hex(4)}"
    expected_audience = f"mcp-{client_name.lower().replace(' ', '-')}"

    reg_payload = {
        "client_name": client_name,
        "redirect_uris": [redirect_uri],
        "audience": expected_audience
    }

    reg_res = client.post("/register", json=reg_payload)
    assert reg_res.status_code == 201, f"Registration failed: {reg_res.text}"
    reg_data = reg_res.json()

    assert "client_id" in reg_data
    assert "client_secret" in reg_data
    assert reg_data["client_name"] == client_name
    assert reg_data["audience"] == expected_audience
    assert redirect_uri in reg_data["redirect_uris"]

    client_id = reg_data["client_id"]
    client_secret = reg_data["client_secret"]

    # -------------------------------------------------------------------------
    # b. Generate PKCE code_verifier and code_challenge (S256)
    # -------------------------------------------------------------------------
    code_verifier, code_challenge = generate_pkce_pair()
    assert len(code_verifier) >= 43
    assert len(code_challenge) > 0

    # -------------------------------------------------------------------------
    # c. Authorization Request (/authorize) with PKCE
    # -------------------------------------------------------------------------
    auth_state = secrets.token_urlsafe(16)
    auth_params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "mcp:all",
        "state": auth_state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }

    auth_res = client.get("/authorize", params=auth_params, follow_redirects=False)
    assert auth_res.status_code == 302, f"Authorize did not redirect: {auth_res.text}"
    assert "location" in auth_res.headers

    # Parse authorization code and state from redirect Location
    location = auth_res.headers["location"]
    parsed_loc = urllib.parse.urlparse(location)
    query_params = dict(urllib.parse.parse_qsl(parsed_loc.query))

    assert "code" in query_params, f"No code in redirect query: {location}"
    assert query_params.get("state") == auth_state
    auth_code = query_params["code"]
    assert auth_code.startswith("ac_")

    # -------------------------------------------------------------------------
    # d. Token Exchange (/token) using authorization_code + code_verifier
    # -------------------------------------------------------------------------
    token_payload = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
        "client_id": client_id,
        "client_secret": client_secret
    }

    token_res = client.post("/token", json=token_payload)
    assert token_res.status_code == 200, f"Token exchange failed: {token_res.text}"
    token_data = token_res.json()

    assert "access_token" in token_data
    assert token_data.get("token_type") == "Bearer"
    assert "expires_in" in token_data
    access_token = token_data["access_token"]

    # -------------------------------------------------------------------------
    # e. Verify RS256 JWT signature against RFC 7517 JWKS endpoint
    # -------------------------------------------------------------------------
    jwks_res = client.get("/.well-known/jwks.json")
    assert jwks_res.status_code == 200
    jwks = jwks_res.json()
    assert "keys" in jwks and len(jwks["keys"]) > 0

    jwk = jwks["keys"][0]
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)

    # Decode and verify signature, issuer, and audience
    decoded_jwt = jwt.decode(
        access_token,
        public_key,
        algorithms=["RS256"],
        audience=expected_audience,
        issuer=settings.clean_issuer_url
    )

    assert decoded_jwt["sub"] == client_id
    assert decoded_jwt["client_id"] == client_id
    assert decoded_jwt["aud"] == expected_audience
    assert decoded_jwt["iss"] == settings.clean_issuer_url
    assert decoded_jwt["auth_mode"] == "oauth2_code"
    assert decoded_jwt["exp"] > time.time()
    assert "jti" in decoded_jwt


def test_failure_cases(client: TestClient):
    """
    Explicitly exercises all OAuth 2.1 failure modes:
    - Wrong code_verifier (PKCE mismatch -> 400 invalid_grant)
    - Already used authorization code (Replay -> 400 invalid_grant)
    - Expired authorization code (Expired -> 400 invalid_grant)
    - Token requested with wrong client_secret (401 invalid_client)
    - Unwhitelisted redirect_uri in /authorize (400 invalid_request)
    """
    # 1. Setup registered client
    redirect_uri = "http://localhost:8080/mcp/callback"
    reg_res = client.post("/register", json={
        "client_name": f"Failure Test Client {secrets.token_hex(3)}",
        "redirect_uris": [redirect_uri],
        "audience": f"mcp-fail-{secrets.token_hex(3)}"
    })
    assert reg_res.status_code == 201
    client_info = reg_res.json()
    client_id = client_info["client_id"]
    client_secret = client_info["client_secret"]

    # --- FAILURE CASE 1: Wrong code_verifier (PKCE mismatch) ---
    verifier, challenge = generate_pkce_pair()
    auth_res = client.get("/authorize", params={
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": challenge,
        "code_challenge_method": "S256"
    }, follow_redirects=False)
    assert auth_res.status_code == 302
    code1 = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(auth_res.headers["location"]).query))["code"]

    wrong_verifier = secrets.token_urlsafe(64)  # Does not match challenge
    res_pkce_fail = client.post("/token", json={
        "grant_type": "authorization_code",
        "code": code1,
        "redirect_uri": redirect_uri,
        "code_verifier": wrong_verifier,
        "client_id": client_id,
        "client_secret": client_secret
    })
    assert res_pkce_fail.status_code == 400
    assert res_pkce_fail.json()["error"] == "invalid_grant"

    # --- FAILURE CASE 2: Already-used authorization code (Replay) ---
    verifier2, challenge2 = generate_pkce_pair()
    auth_res2 = client.get("/authorize", params={
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": challenge2,
        "code_challenge_method": "S256"
    }, follow_redirects=False)
    code2 = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(auth_res2.headers["location"]).query))["code"]

    # First exchange succeeds
    res_first = client.post("/token", json={
        "grant_type": "authorization_code",
        "code": code2,
        "redirect_uri": redirect_uri,
        "code_verifier": verifier2,
        "client_id": client_id,
        "client_secret": client_secret
    })
    assert res_first.status_code == 200

    # Second exchange with identical code must be rejected (single-use)
    res_replay = client.post("/token", json={
        "grant_type": "authorization_code",
        "code": code2,
        "redirect_uri": redirect_uri,
        "code_verifier": verifier2,
        "client_id": client_id,
        "client_secret": client_secret
    })
    assert res_replay.status_code == 400
    assert res_replay.json()["error"] == "invalid_grant"

    # --- FAILURE CASE 3: Expired authorization code ---
    verifier3, challenge3 = generate_pkce_pair()
    expired_code = f"ac_exp_{secrets.token_urlsafe(16)}"
    # Insert code with an expiration timestamp in the past
    past_timestamp_ms = int((time.time() - 600) * 1000)
    create_auth_code(
        code=expired_code,
        client_id=client_id,
        audience=client_info["audience"],
        redirect_uri=redirect_uri,
        code_challenge=challenge3,
        code_challenge_method="S256",
        scope="mcp:all",
        expires_at=past_timestamp_ms
    )

    res_expired = client.post("/token", json={
        "grant_type": "authorization_code",
        "code": expired_code,
        "redirect_uri": redirect_uri,
        "code_verifier": verifier3,
        "client_id": client_id,
        "client_secret": client_secret
    })
    assert res_expired.status_code == 400
    assert res_expired.json()["error"] == "invalid_grant"

    # --- FAILURE CASE 4: Wrong client_secret ---
    verifier4, challenge4 = generate_pkce_pair()
    auth_res4 = client.get("/authorize", params={
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": challenge4,
        "code_challenge_method": "S256"
    }, follow_redirects=False)
    code4 = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(auth_res4.headers["location"]).query))["code"]

    res_wrong_secret = client.post("/token", json={
        "grant_type": "authorization_code",
        "code": code4,
        "redirect_uri": redirect_uri,
        "code_verifier": verifier4,
        "client_id": client_id,
        "client_secret": "wrong_secret_tampered_value"
    })
    assert res_wrong_secret.status_code == 401
    assert res_wrong_secret.json()["error"] == "invalid_client"

    # --- FAILURE CASE 5: Unwhitelisted redirect_uri in /authorize ---
    res_bad_uri = client.get("/authorize", params={
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": "http://evil-attacker.com/steal-token",
        "code_challenge": challenge4,
        "code_challenge_method": "S256"
    }, follow_redirects=False)
    assert res_bad_uri.status_code == 400
    assert res_bad_uri.json()["error"] == "invalid_request"
