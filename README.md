# AdGuard Admin

A fleet manager for multiple [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome)
servers. The admin app is the **source of truth** for your custom DNS records: you
define them once, group your servers into zones, and the reconciliation engine
pushes the desired state to every server — automatically re-applying it whenever a
server comes back online.

![AdGuard Admin walkthrough](docs/images/walkthrough.gif)

> **One control plane for your whole DNS fleet** — declare records and settings once,
> and let reconciliation keep every AdGuard Home box in sync.
>
> 📖 **New here? Start with the [documentation](docs/README.md).**

## Features

- **Zones** — group servers logically (`on-prem`, `cloud`, `iot-vlan`, …).
- **DNS records** — *global* (every server) or *zone-scoped* (only servers in a zone).
- **DNS settings** — manage **upstream DNS servers** and per-domain **forward zones**
  at global / zone / server scope; opt-in per server via *Manage upstreams*.
- **Filtering** — manage **blocklists**, **allowlists** and **blocked services** at
  global / zone / server scope, with a built-in catalog of popular lists ready to enable;
  opt-in per server via *Manage filtering*.
- **Reconciliation** — a background loop diffs desired vs. actual DNS rewrites (and
  upstreams) on each server and applies the difference. Offline servers are retried
  until they converge.
- **Import** — pull a server's existing rewrites *and* upstream config into the admin DB.
- **Provisioning** — one-line, token-based install of new servers (Docker or bare-metal)
  with optional server-side TLS cert.
- **Automatic updates** — keep the AdGuard Home **installations** current, not just
  their config: bare-metal boxes are upgraded over AdGuard's own control API on a
  schedule (with an optional maintenance window), and Docker hosts get a one-line
  on-box updater that pulls the image and recreates the container.
- **Dashboard metrics** — combined query/blocked stats across the fleet, filterable by
  zone and server.
- **Users & RBAC** — `admin` / `editor` / `viewer` roles.
- **OIDC single sign-on** — any OpenID Connect provider, alongside local accounts.
- **Stack** — single-container FastAPI + SQLModel backend serving a Vue 3 SPA styled
  after AdGuard Home.

## Screenshots

|  |  |
|---|---|
| **Dashboard** — fleet-wide query/blocked metrics | **Query log** — combined, searchable, per-server |
| [![Dashboard](docs/images/dashboard.png)](docs/images/dashboard.png) | [![Query log](docs/images/query-log.png)](docs/images/query-log.png) |
| **DNS records** — global & zone-scoped rewrites | **DNS settings** — upstreams & forward zones |
| [![DNS records](docs/images/records.png)](docs/images/records.png) | [![DNS settings](docs/images/dns-settings.png)](docs/images/dns-settings.png) |
| **Servers** — status, version, sync state | **Provisioning** — one-line server installs |
| [![Servers](docs/images/servers.png)](docs/images/servers.png) | [![Provisioning](docs/images/provision.png)](docs/images/provision.png) |

## Documentation

Full guides live in [`docs/`](docs/README.md):

| Guide | What it covers |
|---|---|
| [Getting started](docs/getting-started.md) | Run with Docker, log in, add your first server |
| [Core concepts](docs/concepts.md) | Source-of-truth, zones, scopes, reconciliation, prune |
| [Zones & DNS records](docs/zones-and-records.md) | Grouping servers and managing rewrites |
| [Servers](docs/servers.md) | Adding, testing, importing, per-server behavior |
| [DNS settings](docs/dns-settings.md) | Upstream resolvers and forward zones |
| [Filtering](docs/filtering.md) | Blocklists, allowlists and blocked services |
| [Provisioning](docs/provisioning.md) | One-line install of new AdGuard servers |
| [Updates](docs/updates.md) | Keeping the AdGuard Home containers/binaries themselves up to date |
| [Dashboard & query log](docs/dashboard-and-query-log.md) | Fleet metrics and the combined query log |
| [Users & SSO](docs/users-and-sso.md) | Roles and OIDC single sign-on |
| [Configuration reference](docs/configuration.md) | Every environment variable |

## How the source-of-truth model works

For each enabled server, its **desired** rewrite set is:

```
desired(server) = { enabled global records } ∪ { enabled records in server.zone }
```

The engine reads the server's current DNS rewrites (`/control/rewrite/list`), adds
anything missing, and — only if **prune** is enabled for that server — removes
rewrites that aren't in the desired set. Prune is **off by default**, so the app
never deletes records it didn't create unless you opt in per server.

## Quick start (Docker)

The whole app ships as a **single container**: a multi-stage build compiles the
Vue SPA and bakes it into the FastAPI image, which serves both the UI and the API
on one port.

```bash
cd adguard-admin
cat > .env <<EOF
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
FERNET_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
ADMIN_USERNAME=admin
ADMIN_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")
PUBLIC_BASE_URL=http://localhost:8080
FRONTEND_URL=http://localhost:8080
CORS_ORIGINS=http://localhost:8080
EOF

docker compose up --build
```

Everything is served on **<http://localhost:8080>**:

- UI: <http://localhost:8080>
- API docs: <http://localhost:8080/docs>

Log in with the bootstrap admin and **change the password immediately** (Users page).

## Local development

**Backend**

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # then fill in SECRET_KEY and FERNET_KEY
uvicorn app.main:app --reload
```

**Frontend**

```bash
cd frontend
npm install
npm run dev                   # http://localhost:5173, proxies /api to :8000
```

## Package registry

Builds and CI can install from an internal caching registry (**minireg**) instead
of public PyPI/npm, so dependencies come from a proxy that enforces a CVE block
policy. It is **opt-in and off by default** — a clean clone builds against the
public registries with no configuration.

The registry's address is deliberately not in this repository. It comes from the
environment:

| Where | How to point it inward |
|---|---|
| Your machine | `minireg configure` — writes `~/.npmrc` and `~/.config/pip/pip.conf` |
| CI | Set `MINIREG_ENABLED=true` plus `MINIREG_URL` / `MINIREG_TOKEN` (and `MINIREG_IP` where the runner can't resolve internal DNS) in **Settings → CI/CD → Variables**. `.gitlab-ci.yml` derives `PIP_INDEX_URL` and `NPM_CONFIG_REGISTRY` from them. |
| `docker build` | `--build-arg PIP_INDEX_URL=… --build-arg NPM_CONFIG_REGISTRY=…`, plus `--add-host` if the build container can't resolve it. Both are build-time only, so no internal address is baked into the image. |

`frontend/package-lock.json` keeps upstream `registry.npmjs.org` URLs on purpose:
npm's default `replace-registry-host=npmjs` rewrites them to whichever registry
is configured, so one lockfile works inside and outside the network.

> **`npm audit` does not work against the internal registry.** It asks the
> *configured registry* for advisories, and minireg does not serve npm's
> bulk-advisory endpoint — so it reports "found 0 vulnerabilities" for a tree the
> public registry flags as high. CI runs `npm audit` only when pointed at the
> public registry, and `minireg audit --fail-on medium` otherwise; a gate that
> cannot fail is worse than no gate.

## OIDC / SSO

AdGuard Admin supports OpenID Connect single sign-on alongside local accounts,
with optional group→role mapping. The client is provider-agnostic — only the
issuer and client credentials are configured, everything else comes from the
provider's discovery document — and is tested with Kanidm and Authentik.
`OIDC_DISPLAY_NAME` sets the name on the login button. See
[Users & SSO](docs/users-and-sso.md) for the full setup, and the
[configuration reference](docs/configuration.md#oidc-single-sign-on) for every
variable.

## Security notes

- **The app refuses to start** with a placeholder `SECRET_KEY`, a missing or malformed
  `FERNET_KEY`, a default bootstrap password, a wildcard CORS origin, or an invalid
  OIDC role. It prints every problem and exits.
- AdGuard server passwords are encrypted at rest with `FERNET_KEY`. The backend
  refuses to store them if the key is unset. Revealing one is admin-only, done over
  `POST` so it never reaches a URL log, and audit-logged.
- JWTs are signed with `SECRET_KEY`; decode pins the algorithm to prevent
  algorithm-confusion attacks. Authorization re-reads the user from the database on
  every request, so disabling, deleting or demoting an account takes effect at once.
- Local logins are rate-limited per IP and per username.
- Provisioning input that reaches the root-run `install.sh` is validated and
  shell-quoted; the endpoints serving the admin password and TLS private key are
  single-fetch.
- The embedded AdGuard UI runs in this app's origin — AdGuard's own UI requires
  `localStorage`, so it cannot be sandboxed into an opaque origin. Embedding a
  server means trusting it with your admin session; the app says so at startup,
  and `UI_PROXY_ENABLED=false` turns the feature off.
- Every response carries a strict CSP plus `X-Frame-Options`, `X-Content-Type-Options`,
  `Referrer-Policy` and `Cross-Origin-Opener-Policy` (HSTS too, over HTTPS).
- The application process runs as uid 10001 with no effective capabilities, a
  read-only `/app`, and a `HEALTHCHECK`. Upgrading from a pre-hardening image?
  The entrypoint takes ownership of the existing `/data` volume on first start —
  see [upgrading from a root-era image](docs/configuration.md#upgrading-from-a-root-era-image).
- Dependency versions are pinned to patched releases — see `backend/requirements.txt`
  for the CVEs each pin addresses (python-jose→PyJWT, passlib→pwdlib, Authlib ≥1.7.2,
  Starlette ≥1.3.1, cryptography ≥50.0.0, idna ≥3.15). Transitive packages that a
  scanner attributes to us carry explicit floors, including the dev toolchain's own
  (`pytest`, `filelock`, `pip`), since a floor is the only way to hold a transitive
  dependency to a patched release. The images upgrade `pip` before installing, because
  the base image's own pip ships with advisories and stays in the final layer.
  CI runs `pip-audit`, an npm-side audit and `osv-scanner` on every pipeline.

## Running the tests

```bash
docker build -f backend/Dockerfile.test -t adguard-admin-test backend
docker run --rm adguard-admin-test              # pytest
docker run --rm adguard-admin-test ruff check app tests
```

## API overview

| Method | Path | Role | Purpose |
|---|---|---|---|
| POST | `/api/auth/token` | — | Local login (returns JWT) |
| GET | `/api/auth/oidc/login` | — | Start OIDC flow |
| GET | `/api/stats` | viewer | Dashboard counters |
| CRUD | `/api/zones` | editor | Manage zones |
| CRUD | `/api/servers` | editor | Manage servers (`/test` probes a server) |
| CRUD | `/api/records` | editor | Manage DNS records |
| POST | `/api/sync/run[/{id}]` | editor | Trigger reconciliation |
| GET | `/api/updates` | viewer | Fleet update posture |
| POST | `/api/updates[/{id}]/run` | editor | Update AdGuard Home itself |
| CRUD | `/api/users` | admin | Manage users |

## License

Released under the [MIT License](LICENSE).
