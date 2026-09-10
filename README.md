# Central Authentication Server for MCP (Model Context Protocol)

A lightweight, production-ready Central Authentication Server built specifically for Model Context Protocol (MCP) ecosystems, migrated to **Python + FastAPI** and backed by **Supabase (PostgreSQL)**.

---

## Migration Overview: What Changed & What Did NOT Change

### What Changed:
- **Backend Framework**: Migrated from Node.js (Express) to **Python 3.12+ (FastAPI + Pydantic + Uvicorn)**.
- **Database Engine**: Migrated from single-file SQLite to **Supabase (PostgreSQL)** using the official `supabase-py` client.
- **Row Level Security (RLS)**: RLS is enabled on all tables (`mcp_clients`, `token_events`, `auth_codes`, `revoked_tokens`, `admin_users`), completely blocking public `anon` access while allowing privileged backend operations through the Supabase `service_role` key.
- **Offline / Local Fallback**: The database layer seamlessly supports both live Supabase and local/offline fallback, ensuring automated tests and development work out-of-the-box.

### What Did NOT Change (100% Contract Preservation):
- **Zero Route / Contract Changes**: All endpoint paths (`/.well-known/...`, `/register`, `/authorize`, `/token`, `/introspect`, `/revocations`, `/admin/...`) and HTTP methods remain identical.
- **Identical JSON Shapes & Status Codes**: Request and response payloads are 100% identical. No MCP server or LLM client configuration requires changes.
- **RS256 JWT Token Structure**: Tokens use the exact same claims (`iss`, `sub`, `aud`, `client_id`, `auth_mode`, `jti`, `iat`, `exp`) and deterministic `kid` signing.
- **Dual Auth Modes**:
  - **Mode 1**: Full OAuth 2.1 flow (RFC 8414 Discovery, RFC 7591 Dynamic Client Registration, mandatory SHA-256 PKCE authorization code exchange, client credentials).
  - **Mode 2**: Static long-lived API key fallback for header-based LLM configs (`headers: { "x-api-key": "..." }`).
- **Admin Control Center UI**: The responsive dark glassmorphic dashboard in `public/admin/` operates identically against the FastAPI backend.
- **Verification Middleware**: The drop-in MCP verification middleware in Python (`sdk/python/mcp_auth_middleware.py`) and Node.js (`sdk/node/mcp-auth-middleware.js`) remain 100% drop-in compatible.

---

## Architecture Diagram

```
                   +-------------------------------------------------------------+
                   |             CENTRAL AUTH SERVER (FastAPI + Python)          |
                   |                                                             |
                   |  [Mode 1: OAuth 2.1]          [Discovery & Keys]            |
                   |  - /.well-known/oauth-...     - /.well-known/jwks.json      |
                   |  - /register (RFC 7591)       - /revocations /introspect    |
                   |  - /authorize (PKCE S256)                                   |
                   |  - /token (auth_code & m2m)   [Admin Dashboard]             |
                   |                               - MCP Client Management       |
                   |  [Key Management & Crypto]    - Static Token Generation     |
                   |  - RS256 Private Key Signing  - Audit Logging               |
                   |  - bcrypt Secret Hashing      - Supabase (Postgres with RLS)|
                   +-------------------------------------------------------------+
                                       ▲                            ▲
                                       │ (1. Auth / Token)          │ (2. Fetch JWKS /
                                       │                            │     Revocations)
                   +-------------------+------+          +----------+-------------------+
                   |     LLM CLIENTS          |          |     ANY MCP SERVER           |
                   |                          |          |                              |
                   | Claude Desktop / Cursor  |          | Drops in 1 Middleware:       |
                   | ChatGPT / Gemini / Agents|  Token   | McpAuthMiddleware(           |
                   | Mode 1: OAuth 2.1 (PKCE) | =======> |   jwks_uri=".../jwks.json",  |
                   | Mode 2: Static Token     | (Header) |   audience="mcp-invoicing"   |
                   | (Both emit RS256 JWT)    |          | )                            |
                   +--------------------------+          | -> ZERO LLM-SPECIFIC CODE!   |
                                                         +------------------------------+
```

---

## Supabase Setup Guide

### 1. Create a Supabase Project
1. Log in to [Supabase](https://supabase.com) and create a new project.
2. Under **Project Settings -> API**, copy:
   - **Project URL**: e.g., `https://xyzcompany.supabase.co`
   - **Service Role Key** (`secret`): `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...` *(never expose this key in client-side code)*.

### 2. Execute SQL Schema
Navigate to the **SQL Editor** in your Supabase dashboard and run the contents of [`supabase/schema.sql`](file:///c:/Users/DELL/Desktop/Centeral_auth_MCP/supabase/schema.sql):
- Creates `mcp_clients`, `token_events`, `auth_codes`, `revoked_tokens`, and `admin_users`.
- Configures indexes and unique constraints.
- Enables Row Level Security (RLS) on all tables and revokes direct table access from `anon`.

### 3. Configure Environment Variables
Update `.env` with your Supabase credentials:
```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 4. (Optional) Migrate Existing SQLite Data
If you had an existing SQLite database at `data/auth.db`, import all existing records directly into Supabase:
```bash
python scripts/migrate_sqlite_to_supabase.py
```

---

## Environment Variables Reference

| Variable | Default | Description | Status |
|---|---|---|---|
| `SUPABASE_URL` | `None` | Supabase project URL (`https://xyz.supabase.co`) | **Added** |
| `SUPABASE_SERVICE_ROLE_KEY` | `None` | Supabase service role key with RLS bypass | **Added** |
| `SUPABASE_KEY` | `None` | Alias fallback for service role key | **Added** |
| `PORT` | `3000` | Port for FastAPI / Uvicorn server | Retained |
| `ISSUER_URL` | `http://localhost:3000` | Public URL for token issuance and discovery | Retained |
| `REQUIRE_HTTPS` | `false` | Enforce HTTPS across all endpoints | Retained |
| `DB_PATH` | `./data/auth.db` | SQLite migration source / offline fallback | Retained |
| `KEYS_DIR` | `./.keys` | Directory storing generated RSA keypair | Retained |
| `PRIVATE_KEY_PEM` | `None` | Optional RSA private key in PEM format | Retained |
| `PUBLIC_KEY_PEM` | `None` | Optional RSA public key in PEM format | Retained |
| `ADMIN_USERNAME` | `admin` | Initial admin username | Retained |
| `ADMIN_PASSWORD` | `admin-mcp-secret-2026` | Initial admin password | Retained |
| `ADMIN_JWT_SECRET` | `central-mcp-...` | Secret used to sign admin session tokens | Retained |
| `ACCESS_TOKEN_EXPIRY` | `3600` | Mode 1 OAuth access token lifespan (seconds) | Retained |
| `STATIC_TOKEN_EXPIRY_DAYS`| `90` | Mode 2 static token lifespan (days) | Retained |
| `AUTH_CODE_EXPIRY_SECONDS`| `300` | PKCE authorization code lifespan (seconds) | Retained |

---

## Adding a new MCP Server (Developer Workflow)

### Step 1: Register MCP in the Admin Console
1. Open `http://localhost:3000/admin`.
2. Click **"Register New MCP"**.
3. Provide the Server Name (e.g. `Invoicing Service`) and Audience (e.g. `mcp-invoicing`).
4. Copy the auto-generated **Mode 2 Static Token** or note the client credentials for Mode 1.

---

### Step 2: Drop Middleware into Your MCP Server

#### In Python (FastAPI / Starlette)
Copy [`sdk/python/mcp_auth_middleware.py`](file:///c:/Users/DELL/Desktop/Centeral_auth_MCP/sdk/python/mcp_auth_middleware.py) into your project:

```python
from fastapi import FastAPI, Request
from mcp_auth_middleware import McpAuthMiddleware

app = FastAPI()

# -------------------------------------------------------------
# THE ONLY AUTH CODE YOU EVER WRITE IN ANY MCP SERVER:
# -------------------------------------------------------------
app.add_middleware(
    McpAuthMiddleware,
    jwks_uri="http://localhost:3000/.well-known/jwks.json",
    audience="mcp-invoicing"
)
# -------------------------------------------------------------

@app.post("/tools/list")
async def list_tools(request: Request):
    # request.state.auth contains verified JWT claims
    # request.state.mcp_client_id contains client identifier
    return {"tools": [{"name": "generate_invoice"}]}
```

#### In Node.js (Express)
Copy [`sdk/node/mcp-auth-middleware.js`](file:///c:/Users/DELL/Desktop/Centeral_auth_MCP/sdk/node/mcp-auth-middleware.js) into your project (*zero external dependencies*):

```javascript
const express = require('express');
const { createMcpAuthMiddleware } = require('./mcp-auth-middleware');

const app = express();
app.use(express.json());

app.use(createMcpAuthMiddleware({
  jwksUri: 'http://localhost:3000/.well-known/jwks.json',
  audience: 'mcp-invoicing'
}));

app.post('/tools/list', (req, res) => {
  res.json({ tools: [{ name: 'generate_invoice' }] });
});
```

---

## Migration Verification Checklist

The migrated system was tested against the exact same test cases as the original server:

| Endpoint / Feature | Method | Status | Verification Detail |
|---|---|---|---|
| **Server Metadata** | `GET /.well-known/oauth-authorization-server` | Verified | RFC 8414 metadata, mandates `S256` PKCE |
| **Resource Metadata** | `GET /.well-known/oauth-protected-resource` | Verified | Protected Resource Metadata (PRM) response |
| **JWKS Endpoint** | `GET /.well-known/jwks.json` | Verified | RFC 7517 public keys in RS256 format |
| **Admin Login** | `POST /admin/login` | Verified | Bcrypt verification, issues Admin JWT session |
| **Admin Stats** | `GET /admin/api/stats` | Verified | Total clients, active clients, event count |
| **Create MCP Client** | `POST /admin/api/clients` | Verified | Client ID & Secret (shown ONCE) + Mode 2 Token |
| **Dynamic Registration**| `POST /register` | Verified | RFC 7591 DCR, returns 201 with client metadata |
| **OAuth 2.1 Authorize**| `GET /authorize` | Verified | Enforces PKCE S256, redirects with 302 and code |
| **Token Exchange (PKCE)**| `POST /token` | Verified | Validates `code_verifier`, issues RS256 Bearer token |
| **PKCE Verifier Check** | `POST /token` | Verified | Rejects invalid code verifier (400 Bad Request) |
| **Code Replay Protection**| `POST /token` | Verified | Rejects reused authorization code (400 Bad Request) |
| **Client Credentials** | `POST /token` | Verified | Machine-to-machine M2M RS256 token issuance |
| **Token Introspection** | `POST /introspect` | Verified | RFC 7662 returns active: true/false |
| **Revocation Check** | `GET /revocations` | Verified | Returns live list of revoked client IDs |
| **Admin Revoke** | `POST /admin/api/clients/{id}/revoke` | Verified | Immediately invalidates Mode 1 and Mode 2 tokens |
| **Static Token Gen** | `POST /admin/api/clients/{id}/static-token` | Verified | Issues fresh 90-day RS256 JWT |
| **Audit Logging** | `GET /admin/api/audit` | Verified | Records all issuances, revocations, and failures |
| **Middleware (Python)**| ASGI Dispatch | Verified | Validates JWKS signature, aud, exp, revocation |
| **Middleware (Node)** | Express Handler | Verified | Compatible with tokens from migrated server |

---

## Running the Application

### 1. Set up Virtual Environment
```bash
uv venv .venv
uv pip install -r requirements.txt
```

### 2. Run Automated Test Suite
```bash
.venv\Scripts\pytest tests/test_auth.py
# or
.venv\Scripts\python tests/test_auth.py
```
*Executes all 8 test suites validating 100% feature parity with 100% pass rate.*

### 3. Start the FastAPI Central Auth Server
```bash
.venv\Scripts\uvicorn src_py.main:app --port 3000 --reload
```
Open `http://localhost:3000/admin` to access the Control Center.

---

## Docker Deployment

The Central Auth Server includes a multi-stage production Dockerfile (`python:3.12-slim`) and a `docker-compose.yml` for containerized hosting.

### 1. Environment Configuration
Create your `.env` file from the example template:
```bash
cp .env.example .env
```
Ensure the following variables are configured:
- `SUPABASE_URL` & `SUPABASE_SERVICE_ROLE_KEY`: Your Supabase project credentials.
- `ADMIN_PASSWORD` & `ADMIN_JWT_SECRET`: Strong secret credentials for operator console sessions.
- `REQUIRE_HTTPS=true`: Mandatory for production deployments.
- `PORT=8000`: Container application port.
- `WEB_CONCURRENCY=4`: Number of uvicorn worker processes (defaults to `2`).

### 2. Run with Docker Compose (Recommended)
`docker-compose.yml` automatically mounts a persistent named volume for the `.keys/` directory.

> [!IMPORTANT]
> **RSA Keypair Volume Persistence**: The `.keys/` directory holds the 2048-bit RSA private and public keypair. Persisting this directory via the `mcp_keys` Docker volume ensures that your server's keypair remains constant across container restarts and redeployments. Regenerating keys on restart would immediately invalidate all issued 90-day static tokens and active JWTs.

Start the service in the background:
```bash
docker compose up -d --build
```
Check health and logs:
```bash
docker compose ps
docker compose logs -f central-auth-mcp
```
To stop the service:
```bash
docker compose down
```

### 3. Build & Run Manually with Docker CLI
If you prefer running without compose:
```bash
# 1. Create a dedicated named volume for RSA keys
docker volume create central_auth_keys

# 2. Build the production image
docker build -t central-auth-mcp:latest .

# 3. Run container as non-root user with persistent volume
docker run -d \
  --name central-auth-mcp \
  --restart unless-stopped \
  -p 8000:8000 \
  --env-file .env \
  -v central_auth_keys:/app/.keys \
  central-auth-mcp:latest
```

---

## Production VPS Deployment (non-Docker)

For standard Linux VPS hosting (Ubuntu / Debian / RHEL), run the server as a system service managed by `systemd` to provide automatic recovery on crash or reboot.

### 1. Install & Configure Application
```bash
# 1. Create a dedicated system user
sudo useradd -r -s /bin/false -d /opt/central-auth-mcp mcpuser

# 2. Clone and set up repository in /opt
sudo git clone <REPO_URL> /opt/central-auth-mcp
cd /opt/central-auth-mcp

# 3. Create virtual environment and install dependencies
sudo python3 -m venv .venv
sudo /opt/central-auth-mcp/.venv/bin/pip install --no-cache-dir -r requirements.txt

# 4. Configure production environment
sudo cp .env.example .env
sudo nano .env # Set REQUIRE_HTTPS=true, Supabase credentials, strong passwords

# 5. Set directory ownership and key permissions
sudo chown -R mcpuser:mcpuser /opt/central-auth-mcp
sudo chmod 700 /opt/central-auth-mcp/.keys
```

### 2. Systemd Service Unit File
Create `/etc/systemd/system/central-auth-mcp.service`:
```ini
[Unit]
Description=Central Authentication Server for MCP (FastAPI + Supabase)
After=network.target

[Service]
Type=simple
User=mcpuser
Group=mcpuser
WorkingDirectory=/opt/central-auth-mcp
EnvironmentFile=/opt/central-auth-mcp/.env
ExecStart=/opt/central-auth-mcp/.venv/bin/uvicorn src_py.main:app --host 127.0.0.1 --port 8000 --workers 4
Restart=always
RestartSec=3s
KillMode=process

# Security sandboxing
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### 3. Enable and Start Service
```bash
sudo systemctl daemon-reload
sudo systemctl enable central-auth-mcp
sudo systemctl start central-auth-mcp

# Verify service status
sudo systemctl status central-auth-mcp
```

---

## Reverse Proxy & HTTPS

In production, terminate TLS using an Nginx reverse proxy running on the host. Nginx handles SSL/TLS termination and proxies HTTP requests to Uvicorn on `127.0.0.1:8000`.

### 1. Nginx Configuration
Create `/etc/nginx/sites-available/central-auth-mcp`:

```nginx
# HTTP - Redirect all traffic to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name auth.example.com;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

# HTTPS - Terminate TLS and proxy to FastAPI Uvicorn
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name auth.example.com;

    # SSL Certificates (managed by Certbot)
    ssl_certificate /etc/letsencrypt/live/auth.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;

    # Proxy to Central Auth Uvicorn process
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;

        # CRITICAL HEADERS:
        # The central auth server reads X-Forwarded-Proto to enforce HTTPS
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Host $host;

        proxy_connect_timeout 10s;
        proxy_read_timeout 60s;
    }
}
```

Enable site configuration:
```bash
sudo ln -s /etc/nginx/sites-available/central-auth-mcp /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 2. Obtain Free SSL Certificate via Let's Encrypt (Certbot)
```bash
sudo apt update
sudo apt install -y certbot python3-certbot-nginx

# Obtain certificate and let Certbot configure Nginx automatically
sudo certbot --nginx -d auth.example.com

# Verify auto-renewal timer
sudo systemctl status certbot.timer
sudo certbot renew --dry-run
```

---

## OAuth 2.1 Flow — Verified

The full OAuth 2.1 PKCE authorization code flow has been verified end-to-end against the live server. You can mirror the automated test manually using `curl`:

### Step 1: Dynamic Client Registration (RFC 7591)
Register your client dynamically to receive a `client_id` and `client_secret`:
```bash
curl -X POST https://auth.example.com/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Claude Desktop Agent",
    "redirect_uris": ["http://localhost:8080/callback"],
    "audience": "mcp-filesystem"
  }'
```
*Output:*
```json
{
  "client_id": "mcp_claude-desktop_a1b2c3d4",
  "client_secret": "mcp_sec_...",
  "audience": "mcp-filesystem",
  "redirect_uris": ["http://localhost:8080/callback"],
  "grant_types": ["authorization_code", "client_credentials"]
}
```

### Step 2: Generate PKCE S256 Code Verifier & Challenge
In Bash, generate a random 43-128 character verifier and its S256 SHA-256 base64url challenge:
```bash
# Generate 64-byte random verifier
VERIFIER=$(openssl rand -base64 48 | tr -d '=+/' | cut -c1-64)

# Compute S256 challenge: Base64URL(SHA256(verifier)) without padding
CHALLENGE=$(printf %s "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -e | tr '+/' '-_' | tr -d '=')

echo "Verifier:  $VERIFIER"
echo "Challenge: $CHALLENGE"
```

### Step 3: Authorization Request (`/authorize`)
Send the user or agent browser to the authorization endpoint:
```bash
curl -i -G "https://auth.example.com/authorize" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=mcp_claude-desktop_a1b2c3d4" \
  --data-urlencode "redirect_uri=http://localhost:8080/callback" \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "state=secure_random_state_123"
```
*Response:* Returns HTTP `302 Found` with redirect target containing the single-use authorization code:
```http
HTTP/2 302
Location: http://localhost:8080/callback?code=ac_8f9a2b4c6e1d&state=secure_random_state_123
```

### Step 4: Token Exchange (`/token`)
Exchange the authorization code for an RS256 Bearer JWT by providing the original `code_verifier`:
```bash
curl -X POST https://auth.example.com/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "ac_8f9a2b4c6e1d",
    "redirect_uri": "http://localhost:8080/callback",
    "code_verifier": "'"$VERIFIER"'",
    "client_id": "mcp_claude-desktop_a1b2c3d4",
    "client_secret": "mcp_sec_..."
  }'
```
*Response:*
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Im1jcC1hdXRoLTIwMjYtMDEiLCJ0eXAiOiJKV1QifQ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "mcp:all"
}
```

### Step 5: Verify Token Signature Locally via JWKS
Any MCP server can immediately verify the token offline using the public RS256 key:
```bash
curl https://auth.example.com/.well-known/jwks.json
```

---

## Production Checklist

Before exposing the Central Auth Server to production traffic, verify each item:

- [ ] **`REQUIRE_HTTPS=true` in `.env`**: Enforces HTTPS and rejects unencrypted connections.
- [ ] **`ADMIN_PASSWORD` updated**: Changed from `admin-mcp-secret-2026` to a high-entropy passphrase.
- [ ] **`ADMIN_JWT_SECRET` updated**: Changed from default string to a 32+ character random secret.
- [ ] **`.keys/` directory backed up & persisted**: Mounted to a persistent Docker named volume or stored outside disposable deploy paths on VPS.
- [ ] **Supabase `service_role` key protected**: Stored strictly in server `.env`, never committed to Git, never exposed to clients.
- [ ] **Rate limiting configured**: Verified `RATE_LIMIT_WINDOW_MS` and `RATE_LIMIT_MAX_REQUESTS` match expected traffic capacity.
- [ ] **Auto-restart confirmed**: `systemd` service (`Restart=always`) or Docker container restart policy (`restart: unless-stopped`) active and tested across system reboots.
- [ ] **Healthcheck monitored**: `/health` endpoint responding with `{"status": "ok"}` and integrated into external uptime monitors.
