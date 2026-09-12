import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    port: int = 3000
    issuer_url: str = "http://localhost:3000"
    node_env: str = "development"
    require_https: bool = True

    # Supabase Configuration
    supabase_url: Optional[str] = None
    supabase_service_role_key: Optional[str] = None
    supabase_key: Optional[str] = None  # fallback alias

    # SQLite fallback / migration source path
    db_path: str = "./data/auth.db"

    # RS256 Key Configuration
    keys_dir: str = "./.keys"
    private_key_pem: Optional[str] = None
    public_key_pem: Optional[str] = None

    # Admin Authentication
    admin_username: str = "admin"
    admin_password: str = "admin-mcp-secret-2026"
    admin_jwt_secret: str = "central-mcp-admin-jwt-secret-session-key"

    # Token Lifetimes
    access_token_expiry: int = 3600  # 1 hour in seconds
    static_token_expiry_days: int = 365  # 1 year default (3650 for no-expiry)
    auth_code_expiry_seconds: int = 300  # 5 minutes

    # Rate Limiting
    rate_limit_window_ms: int = 900000
    rate_limit_max_requests: int = 300

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def clean_issuer_url(self) -> str:
        return self.issuer_url.rstrip("/")

    @property
    def effective_supabase_key(self) -> Optional[str]:
        return self.supabase_service_role_key or self.supabase_key


settings = Settings()
