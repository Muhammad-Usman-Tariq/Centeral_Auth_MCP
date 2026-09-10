import os
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from src_py.config import settings
from src_py.crypto.keys import init_keys
from src_py.db.models import init_db
from src_py.routers import well_known, oauth, admin


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize Keys and Database
    print("--- Central Auth Server for MCP (FastAPI + Supabase) ---")
    init_keys()
    init_db()
    print(f"[Server] Issuer URL: {settings.clean_issuer_url}")
    print(f"[Server] Discovery:  {settings.clean_issuer_url}/.well-known/oauth-authorization-server")
    print(f"[Server] JWKS:       {settings.clean_issuer_url}/.well-known/jwks.json")
    print(f"[Server] Admin UI:   {settings.clean_issuer_url}/admin")
    if not settings.require_https:
        print("[SECURITY WARNING] REQUIRE_HTTPS is False — do not use this configuration in production.")
    print("---------------------------------------------------------")
    yield
    # Shutdown logic if any
    print("[Server] Shutting down...")


app = FastAPI(
    title="Central Auth Server for MCP",
    description="Unified OAuth 2.1 & Static Token Hub for Model Context Protocol servers",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# HTTPS Enforcement Middleware (in production when configured)
@app.middleware("http")
async def enforce_https(request: Request, call_next):
    if settings.require_https:
        # Check X-Forwarded-Proto header (handles proxies like Nginx, comma-separated, case-insensitive)
        fwd_proto = request.headers.get("x-forwarded-proto", "")
        proto = fwd_proto.split(",")[0].strip().lower() if fwd_proto else request.url.scheme
        if proto != "https":
            if request.method in ["GET", "HEAD"]:
                url = request.url.replace(scheme="https")
                return RedirectResponse(url=str(url), status_code=301)
            return JSONResponse(
                status_code=403,
                content={
                    "error": "https_required",
                    "error_description": "HTTPS connection is strictly required for this endpoint."
                }
            )
    return await call_next(request)


# Include Routers
app.include_router(well_known.router)
app.include_router(oauth.router)
app.include_router(admin.router)

# Mount Admin Dashboard Static UI
admin_static_dir = Path(__file__).resolve().parent.parent / "public" / "admin"
if admin_static_dir.exists():
    app.mount("/admin", StaticFiles(directory=str(admin_static_dir), html=True), name="admin")


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/admin")


@app.get("/health", tags=["Health"])
def health_check():
    import datetime
    return {
        "status": "ok",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src_py.main:app", host="0.0.0.0", port=settings.port, reload=True)
