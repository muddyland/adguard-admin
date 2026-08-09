# Configuration reference

All configuration is via environment variables (read from `.env` in development, or the
container environment in production). Defaults are shown; values you should override in
production are flagged.

## Core

| Variable | Default | Notes |
|---|---|---|
| `APP_NAME` | `AdGuard Admin` | Display name. |
| `DATABASE_URL` | `sqlite:///./adguard_admin.db` | The Docker image uses `sqlite:////data/adguard_admin.db` on a persistent volume. |
| `DB_POOL_SIZE` | `10` | Pooled database connections. |
| `DB_MAX_OVERFLOW` | `20` | Extra connections allowed above the pool size under load. |
| `DB_POOL_TIMEOUT_SECONDS` | `10` | How long a request waits for a free connection before erroring. Deliberately short: a long wait reads as a hung UI.

## Security — required

**The app refuses to start** if any of these is missing or left at a placeholder.
Startup prints every problem it found and exits; fix them all, or set
`ALLOW_INSECURE_CONFIG=true` for local development only.

| Variable | Default | Notes |
|---|---|---|
| `SECRET_KEY` | _(insecure placeholder)_ | **Required, min 32 chars.** Signs JWTs and the OIDC session. Generate: `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`. Startup rejects the shipped placeholder — anyone who has read this repository could otherwise forge an admin token. |
| `FERNET_KEY` | _(empty)_ | **Required.** Encrypts AdGuard server passwords at rest. Generate: `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. Validated at startup, so a malformed key fails fast instead of surfacing as a per-server sync error. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `720` | JWT lifetime (12h). |
| `JWT_ALGORITHM` | `HS256` | Signing algorithm (pinned on decode). |
| `ALLOW_INSECURE_CONFIG` | `false` | Downgrades the startup checks above to warnings. **Local development only.** |

## Bootstrap admin

Created only on first start, when no users exist.

| Variable | Default | Notes |
|---|---|---|
| `ADMIN_USERNAME` | `admin` | Bootstrap admin username. |
| `ADMIN_PASSWORD` | `admin` | **Required.** Startup rejects the literal value `admin`. Rotate it after first login. |

## Login brute-force protection

Failed logins are counted per client IP *and* per username; exceeding the budget
returns `429` with a `Retry-After` header. Counters reset on a successful login.
State is per-process — if you run multiple workers, also rate-limit at your
reverse proxy.

| Variable | Default | Notes |
|---|---|---|
| `LOGIN_MAX_ATTEMPTS` | `10` | Failures allowed inside the window. |
| `LOGIN_WINDOW_SECONDS` | `300` | Sliding window for counting failures. |
| `LOGIN_LOCKOUT_SECONDS` | `300` | How long a tripped key stays locked. |

## Reconciliation

| Variable | Default | Notes |
|---|---|---|
| `SYNC_INTERVAL_SECONDS` | `60` | How often the engine reconciles every server. |
| `SYNC_MAX_CONCURRENCY` | `8` | Servers reconciled in parallel. Raise it if a cycle can't finish within `SYNC_INTERVAL_SECONDS` — each unreachable server costs a full timeout. |
| `ADGUARD_TIMEOUT_SECONDS` | `10` | Per-request timeout when talking to an AdGuard instance. |
| `DEFAULT_PRUNE` | `false` | Default value of [prune](concepts.md#prune) for new servers. Per-server overridable. |

Reconciliation is serialised **per server**, not globally: a manual sync never
waits for the rest of the fleet. If a server is already being reconciled, the
second request reports that and returns immediately rather than queueing. If a
periodic cycle overruns `SYNC_INTERVAL_SECONDS`, the next tick is skipped (and
logged) instead of piling up.

Database connections are never held while talking to an AdGuard instance, so a
fleet of slow or unreachable servers cannot starve the API of connections.

## Embedded AdGuard UI proxy

Renders a managed server's own AdGuard interface inside the admin SPA.

**This is a trust decision, not a sandboxed one.** The proxied HTML and
JavaScript are written by the remote AdGuard instance and run in *this app's*
origin, so a compromised or hostile managed server can read your admin session
token out of `localStorage`.

Confining the frame to an opaque origin (an iframe `sandbox` without
`allow-same-origin`) was tried and does not work. AdGuard Home's dashboard reads
`window.localStorage` from an inline script and `document.cookie` from its main
bundle; both throw `SecurityError` in an opaque origin and its UI never starts.
Verified against AdGuard Home v0.107.78. The app logs this trade-off at startup.

If you do not trust every managed server, set `UI_PROXY_ENABLED=false`. The
*Open UI in new tab* action still works and involves no proxying at all.

| Variable | Default | Notes |
|---|---|---|
| `UI_PROXY_ENABLED` | `true` | Set to `false` to remove the embedded-UI feature entirely. |
| `PROXY_TOKEN_TTL_MINUTES` | `60` | Lifetime of the path-scoped UI session cookie. The cookie's user is re-checked against the database on every request, so disabling or demoting a user revokes access immediately. |

`/api/servers/{id}/ui-session` reports the active mode in its `isolation` field
(currently always `same-origin`) and the `sandbox` attribute the SPA applies.

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
| `CORS_ORIGINS` | `http://localhost:5173,http://localhost:8000` | Comma-separated allowed origins. `*` is rejected at startup: credentialed requests are enabled, so a wildcard is never valid here. |

Setting `PUBLIC_BASE_URL` to an `https://` URL also marks cookies `Secure` and
enables HSTS.

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
| `OIDC_DEFAULT_ROLE` | `viewer` | Role for first-time SSO users. Validated at startup. |
| `OIDC_ADMIN_GROUP` | _(empty)_ | Members of this IdP group become admins. |
| `OIDC_ALLOW_USERNAME_LINKING` | `false` | Let an OIDC identity adopt a pre-existing local account with a matching username. Off by default: many IdPs let users choose their own `preferred_username`, which would allow claiming someone else's account. Even when enabled, an account that has a local password is never adopted. |

Only an email the provider marked `email_verified` is trusted; an unverified
address is self-asserted and is ignored.

## Security notes

- **Startup gate.** The app refuses to run with placeholder secrets, a default
  bootstrap password, a wildcard CORS origin, an invalid OIDC role, or a
  malformed Fernet key. See the table above.
- **Passwords at rest.** AdGuard server passwords are encrypted with `FERNET_KEY`;
  the backend refuses to store them if the key is unset. Revealing a stored
  password is an admin-only `POST` (never a `GET`, so it stays out of browser
  history and access logs) and is written to the audit log.
- **Tokens.** JWTs are signed with `SECRET_KEY` and decode pins the algorithm.
  Authorization always re-reads the user from the database, so disabling,
  deleting, or demoting a user takes effect immediately rather than at expiry.
- **Provisioning.** Values that reach the root-run `install.sh` are validated on
  input and shell-quoted on output. The endpoints serving the generated admin
  password and the TLS private key are **single-fetch** — a replay of the
  (log-visible) token URL returns `410`.
- **Response headers.** A strict CSP, `X-Frame-Options: DENY`,
  `X-Content-Type-Options`, `Referrer-Policy` and `Cross-Origin-Opener-Policy` are
  set on every response except the UI proxy, which is isolated by iframe
  sandboxing instead.
- **Container.** The application process runs as uid 10001 with no effective
  capabilities and a read-only `/app`; only `/data` is writable. A `HEALTHCHECK`
  polls `/api/health`. See [upgrading from a root-era image](#upgrading-from-a-root-era-image).
- Dependency versions are pinned to patched releases — see `backend/requirements.txt`
  for the CVEs each pin addresses. CI runs `pip-audit`, `npm audit` and
  `osv-scanner` on every pipeline.

## Upgrading from a root-era image

Builds before the security hardening ran the container as **root**, so any
`/data` volume they created contains root-owned files. The app now runs as uid
10001, which cannot write them — SQLite reports this as the rather unhelpful:

```
sqlite3.OperationalError: attempt to write a readonly database
```

**You do not normally need to do anything.** The container starts as root purely
so its entrypoint can take ownership of `/data`, then immediately drops to uid
10001 before exec'ing the app. You will see this once, on the first start after
upgrading:

```
entrypoint: /data is not writable by uid 10001; taking ownership
entrypoint: ownership of /data updated
```

The application process itself never runs as root.

If you have overridden `user:` in your compose file, or dropped `CAP_CHOWN`, the
entrypoint cannot repair the volume and will say so. Fix it once by hand:

```bash
docker compose run --rm --user root --entrypoint sh app -c 'chown -R 10001:10001 /data'
docker compose up -d
```

Once the volume is correct you can pin `user: "10001:10001"` in compose to skip
the root phase entirely.
