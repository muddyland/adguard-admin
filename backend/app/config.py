from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

# Values that mean "the operator never set a real secret". Startup refuses to
# continue on any of these unless ALLOW_INSECURE_CONFIG=true.
PLACEHOLDER_SECRETS = {
    "",
    "change-me-please-generate-a-long-random-string",
    "changeme",
    "change-me",
    "secret",
    "supersecret",
}

MIN_SECRET_KEY_LENGTH = 32

VALID_ROLES = {"admin", "editor", "viewer"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Core
    app_name: str = "AdGuard Admin"
    database_url: str = "sqlite:///./adguard_admin.db"

    # Connection pool. FastAPI serves sync endpoints from a thread pool, so
    # concurrent requests each need a connection.
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_pool_timeout_seconds: int = 10

    # Security — MUST be overridden in production via .env
    secret_key: str = "change-me-please-generate-a-long-random-string"
    # Fernet key used to encrypt AdGuard server passwords at rest.
    # Generate with:  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    fernet_key: str = ""
    access_token_expire_minutes: int = 60 * 12
    jwt_algorithm: str = "HS256"

    # Downgrade the startup config checks from fatal errors to warnings. Only for
    # local development — never set this in a deployment.
    allow_insecure_config: bool = False

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
    # How many servers to reconcile at once. The loop used to be strictly
    # sequential, so a fleet of slow/unreachable servers could not finish a cycle
    # within sync_interval_seconds.
    sync_max_concurrency: int = 8
    # Per-request timeout when talking to an AdGuard instance.
    adguard_timeout_seconds: float = 10.0
    # If True, the engine removes DNS rewrites on a server that are not part of
    # the desired (managed) state. Off by default so we never touch records the
    # admin app didn't create. Can be toggled per-server.
    default_prune: bool = False

    # --- Automatic AdGuard Home updates (see app.updater) ------------------ #
    # Master switch. Even when on, a server is only upgraded if its own
    # auto_update flag is set, so this never surprises an existing fleet.
    auto_update_enabled: bool = True
    # Default for the auto_update flag of newly added / provisioned servers.
    auto_update_default: bool = False
    # How often the updater looks for eligible servers.
    auto_update_interval_seconds: int = 3600
    # Maintenance window, "HH:MM-HH:MM" in UTC. Empty means any time. A window
    # may wrap midnight (e.g. "23:00-02:00"). An upgrade restarts AdGuard Home,
    # which briefly stops DNS resolution for everything behind it.
    auto_update_window: str = ""
    # How long to wait before retrying a server whose upgrade failed.
    auto_update_retry_hours: int = 6
    # How long to wait for a server to come back on the new version.
    auto_update_restart_timeout_seconds: float = 300.0
    # How many servers to upgrade at once. Deliberately 1: rolling one box at a
    # time keeps the rest of the fleet resolving while one restarts.
    auto_update_max_concurrency: int = 1

    # Login brute-force protection (in-process; see app.ratelimit).
    login_max_attempts: int = 10
    login_window_seconds: int = 300
    login_lockout_seconds: int = 300

    # --- Embedded AdGuard UI proxy -----------------------------------------
    # Serves a remote AdGuard instance's own HTML/JS through our origin so it
    # can be embedded. AdGuard's UI requires localStorage and document.cookie,
    # so the frame must run same-origin and the proxied instance is therefore
    # trusted with this app's origin. Turn this off if you do not trust every
    # managed server.
    ui_proxy_enabled: bool = True
    proxy_token_ttl_minutes: int = 60

    # OIDC (all optional — OIDC is disabled unless issuer is set). Nothing here
    # is provider-specific: everything past the issuer and the client
    # credentials comes out of the provider's discovery document.
    oidc_enabled: bool = False
    oidc_issuer: str = ""  # e.g. https://idm.example.com/oauth2/openid/adguard-admin
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    # Name of your identity provider, shown on the login button ("Sign in with
    # Kanidm"). Purely cosmetic.
    oidc_display_name: str = "SSO"
    # Kanidm only emits the `groups` claim when the `groups` scope is asked for;
    # Authentik folds groups into `profile`. Add `groups` here if you use
    # OIDC_ADMIN_GROUP and your provider needs it.
    oidc_scopes: str = "openid email profile"
    # Send a PKCE (S256) challenge on the authorization request. Kanidm rejects
    # the request without one. Harmless everywhere else, so it is on by default;
    # turn it off only for a provider that chokes on the extra parameters.
    oidc_pkce: bool = True
    # Where the provider redirects back to — must match the client config.
    oidc_redirect_uri: str = "http://localhost:8000/api/auth/oidc/callback"
    # After login the user is bounced back to the SPA here.
    frontend_url: str = "http://localhost:5173"
    # Users who sign in via OIDC for the first time get this role.
    oidc_default_role: str = "viewer"
    # Optional provider group whose members become admins. Kanidm names groups
    # by SPN ("adguard-admins@idm.example.com"); either form works here.
    oidc_admin_group: str = ""
    # Adopt a pre-existing local account when the OIDC username matches it. Off
    # by default: if the IdP lets users choose their own preferred_username,
    # turning this on allows claiming any local account (including 'admin').
    oidc_allow_username_linking: bool = False

    cors_origins: str = "http://localhost:5173,http://localhost:8000"

    # ----------------------------------------------------------------------- #
    # Derived helpers
    # ----------------------------------------------------------------------- #
    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def oidc_button_label(self) -> str:
        """Label for the SPA's SSO button, e.g. "Sign in with Kanidm"."""
        return f"Sign in with {self.oidc_display_name.strip() or 'SSO'}"

    @property
    def secure_cookies(self) -> bool:
        """Mark cookies Secure when this app is reached over HTTPS."""
        return self.public_base_url.lower().startswith("https")


def parse_window(value: str) -> tuple[int, int] | None:
    """Parse "HH:MM-HH:MM" into minutes-since-midnight. None means "any time".

    Raises ValueError on anything malformed, so a typo in AUTO_UPDATE_WINDOW is
    caught at startup rather than silently disabling the window.
    """
    text = (value or "").strip()
    if not text:
        return None
    try:
        start_s, end_s = text.split("-", 1)
        start = _minutes(start_s)
        end = _minutes(end_s)
    except ValueError as exc:
        raise ValueError(
            f"{value!r} is not a time window of the form HH:MM-HH:MM (24h, UTC)"
        ) from exc
    if start == end:
        raise ValueError(f"{value!r} is an empty window: start and end are the same time")
    return start, end


def _minutes(hhmm: str) -> int:
    hours, minutes = hhmm.strip().split(":")
    h, m = int(hours), int(minutes)
    if not (0 <= h <= 23 and 0 <= m <= 59):
        raise ValueError(f"{hhmm!r} is not a valid 24h time")
    return h * 60 + m


def config_problems(s: Settings) -> list[str]:
    """Return a list of fatal misconfigurations. Empty means good to start.

    Kept separate from Settings construction so importing the module never
    raises — startup calls this explicitly and decides what to do.
    """
    problems: list[str] = []

    if s.secret_key.strip().lower() in PLACEHOLDER_SECRETS:
        problems.append(
            "SECRET_KEY is unset or still the placeholder value. Anyone who knows the "
            "default can forge admin tokens. Generate one with: "
            'python -c "import secrets; print(secrets.token_urlsafe(48))"'
        )
    elif len(s.secret_key) < MIN_SECRET_KEY_LENGTH:
        problems.append(
            f"SECRET_KEY is only {len(s.secret_key)} characters; "
            f"at least {MIN_SECRET_KEY_LENGTH} are required."
        )

    if not s.fernet_key.strip():
        problems.append(
            "FERNET_KEY is not set; AdGuard server credentials cannot be encrypted at rest. "
            'Generate one with: python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"'
        )
    else:
        # Fail here rather than deep inside the reconcile loop, where a bad key
        # surfaces as an opaque per-server error.
        try:
            from cryptography.fernet import Fernet

            Fernet(s.fernet_key.encode())
        except Exception as exc:
            problems.append(f"FERNET_KEY is not a valid Fernet key: {exc}")

    if s.admin_password == "admin":
        problems.append(
            "ADMIN_PASSWORD is still 'admin'. Set a real bootstrap password before first start."
        )

    if "*" in s.cors_origin_list:
        problems.append(
            "CORS_ORIGINS contains '*', which cannot be combined with credentialed "
            "requests. List the exact origins instead."
        )

    try:
        parse_window(s.auto_update_window)
    except ValueError as exc:
        problems.append(f"AUTO_UPDATE_WINDOW is invalid: {exc}")

    if s.oidc_default_role not in VALID_ROLES:
        problems.append(
            f"OIDC_DEFAULT_ROLE={s.oidc_default_role!r} is not one of {sorted(VALID_ROLES)}."
        )

    if s.oidc_enabled and not (s.oidc_issuer and s.oidc_client_id and s.oidc_client_secret):
        problems.append(
            "OIDC_ENABLED is true but OIDC_ISSUER / OIDC_CLIENT_ID / OIDC_CLIENT_SECRET "
            "are not all set."
        )

    return problems


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
