"""
Automated Test Suite for Migrated FastAPI + Supabase Central Auth Server
and Drop-in MCP Verification Middleware.

Verifies:
1. RFC 8414 Discovery & RFC 7517 JWKS
2. Admin Authentication & MCP Registration
3. Mode 1: RFC 7591 Dynamic Client Registration
4. Mode 1: Full OAuth 2.1 PKCE Flow (S256 mandatory)
5. Mode 1: Client Credentials M2M Flow
6. Standalone Drop-in MCP Middleware Verification (Mode 1 & Mode 2)
7. Immediate Revocation Invalidation
8. Audit Log Trail Verification
"""

import os
import sys
import time
import base64
import hashlib
import secrets
import threading
import urllib.parse
from pathlib import Path
import re
import requests
import uvicorn
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Add repository root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src_py.main import app
from src_py.config import settings
from src_py.crypto.keys import init_keys
from src_py.db.models import init_db, get_client_by_client_id
from sdk.python.mcp_auth_middleware import McpAuthMiddleware


def test_suite():
    print("\n======================================================")
    print(" RUNNING PYTHON FASTAPI CENTRAL AUTH MCP TEST SUITE")
    print("======================================================\n")

    init_keys()
    init_db()

    # Start live background uvicorn test server on ephemeral dynamic port
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    while not server.started:
        time.sleep(0.02)

    server_port = server.servers[0].sockets[0].getsockname()[1]
    base_url = f"http://127.0.0.1:{server_port}"
    settings.issuer_url = base_url
    print(f"[Test Server] Running at: {base_url}\n")

    session = requests.Session()

    try:
        # -------------------------------------------------------------
        print("\033[36m[TEST 1] Discovery & JWKS Endpoints\033[0m")
        # -------------------------------------------------------------
        disc_res = session.get(f"{base_url}/.well-known/oauth-authorization-server")
        assert disc_res.status_code == 200, f"Discovery failed: {disc_res.text}"
        meta = disc_res.json()
        assert meta["issuer"] == base_url
        assert "S256" in meta["code_challenge_methods_supported"]
        assert "authorization_code" in meta["grant_types_supported"]
        print("  \033[32m[PASS]\033[0m RFC 8414 discovery metadata valid")

        prm_res = session.get(f"{base_url}/.well-known/oauth-protected-resource")
        assert prm_res.status_code == 200
        print("  \033[32m[PASS]\033[0m Protected Resource Metadata (PRM) valid")

        jwks_res = session.get(f"{base_url}/.well-known/jwks.json")
        assert jwks_res.status_code == 200
        jwks = jwks_res.json()
        assert "keys" in jwks and len(jwks["keys"]) > 0
        key = jwks["keys"][0]
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert key["use"] == "sig"
        print("  \033[32m[PASS]\033[0m RFC 7517 JWKS public keys valid")

        # -------------------------------------------------------------
        print("\n\033[36m[TEST 2] Admin Authentication & MCP Registration\033[0m")
        # -------------------------------------------------------------
        login_res = session.post(f"{base_url}/admin/login", json={
            "username": settings.admin_username,
            "password": settings.admin_password
        })
        assert login_res.status_code == 200, f"Login failed: {login_res.text}"
        login_data = login_res.json()
        assert login_data["success"] is True
        admin_token = login_data["token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        print("  \033[32m[PASS]\033[0m Admin login succeeds and returns session JWT")

        test_audience = f"mcp-invoicing-{int(time.time() * 1000)}"
        create_res = session.post(
            f"{base_url}/admin/api/clients",
            json={
                "name": "Python Invoicing Service",
                "audience": test_audience,
                "allowedRedirectUris": ["http://127.0.0.1:9999/callback"],
                "generateStaticToken": True,
                "staticTokenDays": 90
            },
            headers=admin_headers
        )
        assert create_res.status_code == 201, f"Create client failed: {create_res.text}"
        create_data = create_res.json()
        assert create_data["success"] is True
        test_client_id = create_data["client"]["client_id"]
        test_client_secret = create_data["clientSecret"]
        static_token = create_data["staticToken"]["token"]
        assert bool(test_client_id)
        assert bool(test_client_secret)
        assert bool(static_token)
        assert "envSnippet" in create_data
        assert f"JWKS_URI={settings.clean_issuer_url}/.well-known/jwks.json" in create_data["envSnippet"]
        assert f"MCP_AUDIENCE={test_audience}" in create_data["envSnippet"]
        assert f"MCP_AUTH_TOKEN={static_token}" in create_data["envSnippet"]
        print("  \033[32m[PASS]\033[0m Client registered, secret revealed ONCE, static token generated, envSnippet present")

        # -------------------------------------------------------------
        print("\n\033[36m[TEST 2B] One-Field Simplified Registration Flow (Auto-Audience & envSnippet)\033[0m")
        # -------------------------------------------------------------
        # Only provide 'name' — audience and redirect URIs should be auto-generated
        simple_res1 = session.post(
            f"{base_url}/admin/api/clients",
            json={"name": "Invoicing MCP"},
            headers=admin_headers
        )
        assert simple_res1.status_code == 201, f"Simple create 1 failed: {simple_res1.text}"
        simple_data1 = simple_res1.json()
        assert simple_data1["success"] is True

        aud1 = simple_data1["client"]["audience"]
        assert re.match(r"^mcp-invoicing-[0-9a-f]{4,6}$", aud1), f"Unexpected audience format: {aud1}"
        assert "http://127.0.0.1:*" in simple_data1["client"]["allowed_redirect_uris"]
        assert "http://localhost:*" in simple_data1["client"]["allowed_redirect_uris"]
        assert bool(simple_data1["staticToken"]["token"])

        # Validate envSnippet format and content
        snippet1 = simple_data1["envSnippet"]
        expected_snippet1 = (
            f"JWKS_URI={settings.clean_issuer_url}/.well-known/jwks.json\n"
            f"MCP_AUDIENCE={aud1}\n"
            f"MCP_AUTH_TOKEN={simple_data1['staticToken']['token']}"
        )
        assert snippet1 == expected_snippet1, f"Snippet mismatch: {snippet1} != {expected_snippet1}"

        # Register second client with identical name to verify unique random suffix guarantee
        simple_res2 = session.post(
            f"{base_url}/admin/api/clients",
            json={"name": "Invoicing MCP"},
            headers=admin_headers
        )
        assert simple_res2.status_code == 201
        simple_data2 = simple_res2.json()
        aud2 = simple_data2["client"]["audience"]
        assert aud1 != aud2, f"Audiences must be unique! Got {aud1} and {aud2}"
        assert re.match(r"^mcp-invoicing-[0-9a-f]{4,6}$", aud2)

        print(f"  \033[32m[PASS]\033[0m One-field creation generated unique audiences ({aud1}, {aud2}) and valid envSnippet")

        # -------------------------------------------------------------
        print("\n\033[36m[TEST 3] Mode 1: Dynamic Client Registration (RFC 7591)\033[0m")
        # -------------------------------------------------------------
        dcr_aud = f"mcp-claude-{int(time.time() * 1000)}"
        dcr_res = session.post(f"{base_url}/register", json={
            "client_name": "Claude Desktop Agent",
            "audience": dcr_aud,
            "redirect_uris": ["http://127.0.0.1:8080/callback"]
        })
        assert dcr_res.status_code == 201, f"DCR failed: {dcr_res.text}"
        dcr_data = dcr_res.json()
        assert "client_id" in dcr_data
        assert "client_secret" in dcr_data
        assert dcr_data["token_endpoint_auth_method"] == "client_secret_post"
        print("  \033[32m[PASS]\033[0m RFC 7591 Dynamic Client Registration succeeds")

        # -------------------------------------------------------------
        print("\n\033[36m[TEST 4] Mode 1: Full OAuth 2.1 PKCE Authorization Code Flow\033[0m")
        # -------------------------------------------------------------
        code_verifier = secrets.token_urlsafe(32)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode("ascii")).digest()
        ).decode("ascii").rstrip("=")

        # 1. Authorize GET
        auth_params = {
            "response_type": "code",
            "client_id": test_client_id,
            "redirect_uri": "http://127.0.0.1:9999/callback",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": "test_state_123"
        }
        auth_res = session.get(f"{base_url}/authorize", params=auth_params, allow_redirects=False)
        assert auth_res.status_code == 302, f"Auth failed: {auth_res.status_code}"
        location = auth_res.headers.get("location", "")
        assert location.startswith("http://127.0.0.1:9999/callback")
        parsed_loc = urllib.parse.urlparse(location)
        query_dict = dict(urllib.parse.parse_qsl(parsed_loc.query))
        auth_code = query_dict.get("code")
        assert bool(auth_code)
        assert query_dict.get("state") == "test_state_123"
        print("  \033[32m[PASS]\033[0m Authorization endpoint issues code and preserves state")

        # 2. Rejects invalid PKCE code_verifier
        bad_token_res = session.post(f"{base_url}/token", json={
            "grant_type": "authorization_code",
            "client_id": test_client_id,
            "code": auth_code,
            "redirect_uri": "http://127.0.0.1:9999/callback",
            "code_verifier": "wrong-verifier-value"
        })
        assert bad_token_res.status_code == 400
        print("  \033[32m[PASS]\033[0m Rejects invalid PKCE code_verifier")

        # 3. Exchanges code for token with valid code_verifier
        good_token_res = session.post(f"{base_url}/token", json={
            "grant_type": "authorization_code",
            "client_id": test_client_id,
            "code": auth_code,
            "redirect_uri": "http://127.0.0.1:9999/callback",
            "code_verifier": code_verifier
        })
        assert good_token_res.status_code == 200, f"Token exchange failed: {good_token_res.text}"
        token_data = good_token_res.json()
        oauth_access_token = token_data["access_token"]
        assert bool(oauth_access_token)
        assert token_data["token_type"] == "Bearer"
        print("  \033[32m[PASS]\033[0m Successfully exchanged auth code for RS256 token")

        # 4. Code replay fails
        replay_res = session.post(f"{base_url}/token", json={
            "grant_type": "authorization_code",
            "client_id": test_client_id,
            "code": auth_code,
            "redirect_uri": "http://127.0.0.1:9999/callback",
            "code_verifier": code_verifier
        })
        assert replay_res.status_code == 400
        print("  \033[32m[PASS]\033[0m Rejects replayed authorization code")

        # -------------------------------------------------------------
        print("\n\033[36m[TEST 5] Mode 1: Client Credentials Grant (M2M)\033[0m")
        # -------------------------------------------------------------
        cc_res = session.post(f"{base_url}/token", json={
            "grant_type": "client_credentials",
            "client_id": test_client_id,
            "client_secret": test_client_secret
        })
        assert cc_res.status_code == 200
        cc_data = cc_res.json()
        assert bool(cc_data.get("access_token"))
        print("  \033[32m[PASS]\033[0m Client credentials grant issues valid access token")

        # -------------------------------------------------------------
        print("\n\033[36m[TEST 6] Standalone Drop-in MCP Middleware Verification\033[0m")
        # -------------------------------------------------------------
        # Create sample MCP server app protected by McpAuthMiddleware pointing to live test server
        mcp_app = FastAPI()
        mcp_app.add_middleware(
            McpAuthMiddleware,
            jwks_uri=f"{base_url}/.well-known/jwks.json",
            audience=test_audience,
            revocations_uri=f"{base_url}/revocations"
        )

        @mcp_app.post("/tools/list")
        def list_tools():
            return {"tools": [{"name": "invoicing_tool"}]}

        mcp_client = TestClient(mcp_app)

        # A) Mode 1 OAuth 2.1 token in Authorization header
        m1_res = mcp_client.post("/tools/list", headers={"Authorization": f"Bearer {oauth_access_token}"})
        assert m1_res.status_code == 200, f"Mode 1 failed: {m1_res.text}"
        print("  \033[32m[PASS]\033[0m Middleware accepts Mode 1 OAuth 2.1 Bearer token")

        # B) Mode 2 Static Token in x-api-key header
        m2_res = mcp_client.post("/tools/list", headers={"x-api-key": static_token})
        assert m2_res.status_code == 200, f"Mode 2 failed: {m2_res.text}"
        print("  \033[32m[PASS]\033[0m Middleware accepts Mode 2 static token via x-api-key")

        # C) Reject tampered token
        tampered_res = mcp_client.post("/tools/list", headers={"Authorization": f"Bearer {oauth_access_token}bad"})
        assert tampered_res.status_code == 401
        print("  \033[32m[PASS]\033[0m Middleware rejects tampered token")

        # D) Reject mismatched audience
        wrong_aud_app = FastAPI()
        wrong_aud_app.add_middleware(
            McpAuthMiddleware,
            jwks_uri=f"{base_url}/.well-known/jwks.json",
            audience="mcp-wrong-service"
        )
        @wrong_aud_app.post("/tools/list")
        def wrong_list():
            return {"tools": []}

        wrong_client = TestClient(wrong_aud_app)
        wrong_res = wrong_client.post("/tools/list", headers={"x-api-key": static_token})
        assert wrong_res.status_code == 401
        print("  \033[32m[PASS]\033[0m Middleware rejects mismatched audience")

        # -------------------------------------------------------------
        print("\n\033[36m[TEST 7] Immediate Revocation Enforcement\033[0m")
        # -------------------------------------------------------------
        client_rec = get_client_by_client_id(test_client_id)
        revoke_res = session.post(
            f"{base_url}/admin/api/clients/{client_rec['id']}/revoke",
            headers=admin_headers
        )
        assert revoke_res.status_code == 200
        print("  \033[32m[PASS]\033[0m Admin successfully revokes MCP client")

        # Verify that introspect reports active: False
        intro_res = session.post(f"{base_url}/introspect", json={"token": static_token})
        assert intro_res.status_code == 200
        assert intro_res.json()["active"] is False
        print("  \033[32m[PASS]\033[0m Introspect endpoint confirms revoked token is inactive")

        # -------------------------------------------------------------
        print("\n\033[36m[TEST 8] Audit Log Trail Verification\033[0m")
        # -------------------------------------------------------------
        audit_res = session.get(f"{base_url}/admin/api/audit?limit=20", headers=admin_headers)
        assert audit_res.status_code == 200
        events = audit_res.json()["events"]
        assert len(events) > 0
        event_types = [e["event_type"] for e in events]
        assert "issued" in event_types
        assert "revoked" in event_types
        print("  \033[32m[PASS]\033[0m Audit log captures token issuance and client revocation")

        print("\n======================================================")
        print(" ALL TESTS PASSED SUCCESSFULLY! (8/8 Suites)")
        print("======================================================\n")

    finally:
        server.should_exit = True
        thread.join(timeout=2)


if __name__ == "__main__":
    test_suite()
