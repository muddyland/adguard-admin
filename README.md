# AdGuard Admin

A fleet manager for multiple [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome)
servers. The admin app is the **source of truth** for your custom DNS records: you
define them once, group your servers into zones, and the reconciliation engine
pushes the desired state to every server — automatically re-applying it whenever a
server comes back online.

- **Zones** — group servers logically (`on-prem`, `cloud`, `iot-vlan`, …).
- **DNS records** — *global* (every server) or *zone-scoped* (only servers in a zone).
- **DNS settings** — manage **upstream DNS servers** and per-domain **forward zones**
  at global / zone / server scope; opt-in per server via *Manage upstreams*.
- **Reconciliation** — a background loop diffs desired vs. actual DNS rewrites (and
  upstreams) on each server and applies the difference. Offline servers are retried
  until they converge.
- **Import** — pull a server's existing rewrites *and* upstream config into the admin DB.
- **Provisioning** — one-line, token-based install of new servers (Docker or bare-metal)
  with optional server-side TLS cert.
- **Dashboard metrics** — combined query/blocked stats across the fleet, filterable by
  zone and server.
- **Users & RBAC** — `admin` / `editor` / `viewer` roles.
- **OIDC / Authentik** — single sign-on alongside local accounts.
- **Stack** — single-container FastAPI + SQLModel backend serving a Vue 3 SPA styled
  after AdGuard Home.

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
ADMIN_PASSWORD=change-me
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

## OIDC with Authentik

1. In Authentik create an **OAuth2/OpenID Provider** + Application.
   - Redirect URI: `<public-base-url>/api/auth/oidc/callback` (e.g. `http://localhost:8080/api/auth/oidc/callback`)
   - Scopes: `openid email profile` (add a `groups` claim if you want group→role mapping).
2. Set in `.env`:

   ```
   OIDC_ENABLED=true
   OIDC_ISSUER=https://authentik.example.com/application/o/<app-slug>/
   OIDC_CLIENT_ID=...
   OIDC_CLIENT_SECRET=...
   OIDC_REDIRECT_URI=http://localhost:8080/api/auth/oidc/callback
   OIDC_ADMIN_GROUP=adguard-admins     # optional: members become admins
   OIDC_DEFAULT_ROLE=viewer
   ```

3. The login screen shows **Sign in with Authentik**. First-time users are
   provisioned automatically with `OIDC_DEFAULT_ROLE`.

## Security notes

- AdGuard server passwords are encrypted at rest with `FERNET_KEY`. The backend
  refuses to store them if the key is unset.
- JWTs are signed with `SECRET_KEY`; decode pins the algorithm to prevent
  algorithm-confusion attacks.
- Dependency versions are pinned to patched releases — see `backend/requirements.txt`
  for the CVEs each pin addresses (python-jose→PyJWT, passlib→pwdlib, Authlib ≥1.7.2,
  Starlette ≥1.0.1).

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
| CRUD | `/api/users` | admin | Manage users |
```
