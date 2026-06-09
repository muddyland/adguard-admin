from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Core
    app_name: str = "AdGuard Admin"
    database_url: str = "sqlite:///./adguard_admin.db"

    # Security — MUST be overridden in production via .env
    secret_key: str = "change-me-please-generate-a-long-random-string"
    # Fernet key used to encrypt AdGuard server passwords at rest.
    # Generate with:  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    fernet_key: str = ""
    access_token_expire_minutes: int = 60 * 12
    jwt_algorithm: str = "HS256"

    # Bootstrap admin (created on first start if no users exist)
    admin_username: str = "admin"
    admin_password: str = "admin"

    # Provisioning — public URL of THIS admin app, reachable by new servers.
    # Used to build the one-line install command and the script's callbacks.
    public_base_url: str = "http://localhost:8000"
    provision_token_ttl_hours: int = 24
    adguard_default_http_port: int = 3000
    adguard_default_https_port: int = 443
    adguard_dns_port: int = 53

    # Reconciliation loop
    sync_interval_seconds: int = 60
    # If True, the engine removes DNS rewrites on a server that are not part of
    # the desired (managed) state. Off by default so we never touch records the
    # admin app didn't create. Can be toggled per-server.
    default_prune: bool = False

    # OIDC / Authentik (all optional — OIDC is disabled unless issuer is set)
    oidc_enabled: bool = False
    oidc_issuer: str = ""  # e.g. https://authentik.example.com/application/o/adguard-admin/
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_scopes: str = "openid email profile"
    # Where Authentik redirects back to — must match the provider config.
    oidc_redirect_uri: str = "http://localhost:8000/api/auth/oidc/callback"
    # After login the user is bounced back to the SPA here.
    frontend_url: str = "http://localhost:5173"
    # Users who sign in via OIDC for the first time get this role.
    oidc_default_role: str = "viewer"
    # Optional Authentik group whose members become admins.
    oidc_admin_group: str = ""

    cors_origins: str = "http://localhost:5173,http://localhost:8000"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
