# Configuration reference

All configuration is via environment variables (read from `.env` in development, or the
container environment in production). Defaults are shown; values you should override in
production are flagged.

## Core

| Variable | Default | Notes |
|---|---|---|
| `APP_NAME` | `AdGuard Admin` | Display name. |
| `DATABASE_URL` | `sqlite:///./adguard_admin.db` | The Docker image uses `sqlite:////data/adguard_admin.db` on a persistent volume. |

## Security — **set these in production**

| Variable | Default | Notes |
|---|---|---|
| `SECRET_KEY` | _(insecure placeholder)_ | **Required.** Signs JWTs. Use a long random string: `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`. |
| `FERNET_KEY` | _(empty)_ | **Required.** Encrypts AdGuard server passwords at rest. Generate: `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. The backend refuses to store server passwords if unset. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `720` | JWT lifetime (12h). |
| `JWT_ALGORITHM` | `HS256` | Signing algorithm (pinned on decode). |

## Bootstrap admin

Created only on first start, when no users exist.

| Variable | Default | Notes |
|---|---|---|
| `ADMIN_USERNAME` | `admin` | Bootstrap admin username. |
| `ADMIN_PASSWORD` | `admin` | **Change this**, and rotate it after first login. |

## Reconciliation

| Variable | Default | Notes |
|---|---|---|
| `SYNC_INTERVAL_SECONDS` | `60` | How often the engine reconciles every server. |
| `DEFAULT_PRUNE` | `false` | Default value of [prune](concepts.md#prune) for new servers. Per-server overridable. |

## Provisioning

The public URL must be reachable by the servers you [provision](provisioning.md).

| Variable | Default | Notes |
|---|---|---|
| `PUBLIC_BASE_URL` | `http://localhost:8000` | **Externally reachable** URL of this admin app. Used to build install commands and callbacks. |
| `PROVISION_TOKEN_TTL_HOURS` | `24` | How long a provisioning token stays valid. |
| `ADGUARD_DEFAULT_HTTP_PORT` | `3000` | Default admin HTTP port for provisioned servers. |
| `ADGUARD_DEFAULT_HTTPS_PORT` | `443` | Default admin HTTPS port (when TLS is enabled). |
| `ADGUARD_DNS_PORT` | `53` | DNS port for provisioned servers. |

## Networking / CORS

| Variable | Default | Notes |
|---|---|---|
| `FRONTEND_URL` | `http://localhost:5173` | Where OIDC login redirects the SPA back to. With the single-container build, set it to the app's own URL. |
| `CORS_ORIGINS` | `http://localhost:5173,http://localhost:8000` | Comma-separated allowed origins. |

## OIDC / Authentik

All optional; OIDC is off unless `OIDC_ENABLED=true` and an issuer is set. See
[Users & SSO](users-and-sso.md).

| Variable | Default | Notes |
|---|---|---|
| `OIDC_ENABLED` | `false` | Master switch for SSO. |
| `OIDC_ISSUER` | _(empty)_ | e.g. `https://authentik.example.com/application/o/<app-slug>/`. |
| `OIDC_CLIENT_ID` | _(empty)_ | OAuth2 client ID. |
| `OIDC_CLIENT_SECRET` | _(empty)_ | OAuth2 client secret. |
| `OIDC_SCOPES` | `openid email profile` | Requested scopes. |
| `OIDC_REDIRECT_URI` | `http://localhost:8000/api/auth/oidc/callback` | Must match the IdP provider config. |
| `OIDC_DEFAULT_ROLE` | `viewer` | Role for first-time SSO users. |
| `OIDC_ADMIN_GROUP` | _(empty)_ | Members of this IdP group become admins. |

## Security notes

- AdGuard server passwords are encrypted at rest with `FERNET_KEY`; the backend refuses
  to store them if the key is unset.
- JWTs are signed with `SECRET_KEY`; decode pins the algorithm to prevent
  algorithm-confusion attacks.
- Dependency versions are pinned to patched releases — see `backend/requirements.txt`
  for the CVEs each pin addresses.
