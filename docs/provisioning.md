# Provisioning

Provisioning installs a **brand-new AdGuard Home server** and registers it with the
control plane automatically — using a single, token-based, copy-paste command. No manual
setup wizard, no copying credentials around.

![Provisioning](images/provision.png)

## How it works

1. On the **Provisioning** page, click **+ Provision new server** and choose:
   - **Name** and **zone** for the new server.
   - **Method** — `Docker` or `bare-metal` (a native install).
   - **TLS** — optionally issue a self-signed certificate so the new box serves its admin
     API over HTTPS. If enabled, you must give a **connect address** (FQDN or IP) the
     cert is bound to.
   - **Auto-update** — keep AdGuard Home itself current on the new box. For a Docker
     install the script also installs the [on-box updater](updates.md#docker-servers-the-on-box-updater);
     a bare-metal box is upgraded by this app over AdGuard's control API.
2. The app issues a **provisioning token** and shows a one-line command:

   ```bash
   curl -fsSL "https://<your-admin-url>/api/provision/<token>/install.sh" | sudo bash
   ```

   Use **Copy command** to grab it.
3. Run that command on the target machine. The script:
   - installs AdGuard Home (via Docker or natively),
   - configures it with a randomly generated admin password (stored encrypted in the
     admin DB — you never have to handle it),
   - applies TLS if you enabled it,
   - installs the auto-updater if you asked for one (Docker only — see [Updates](updates.md)),
   - and **calls back** to register itself as a managed server.
4. The token flips from **pending** to **completed**, a new entry appears on the
   [Servers](servers.md) page, and the reconciliation engine starts pushing your
   [records](zones-and-records.md) and [settings](dns-settings.md) to it.

## Tokens

- Tokens are **single-use** and **expire** after `PROVISION_TOKEN_TTL_HOURS` (default 24).
- **Revoke** a token any time before it's used; revoked/expired tokens are rejected by
  the install endpoint.
- Toggle **Show revoked** to include inactive tokens in the list.

### Secret endpoints are single-fetch

The token travels in a URL, which means it can end up in shell history, your
terminal scrollback, and the access log of every reverse proxy on both sides. So
the two endpoints that hand out secrets — `/config` (the generated AdGuard admin
password) and `/key.pem` (the TLS private key) — serve them **exactly once**. A
second request returns `410 Gone` and is logged as a possible token leak.

In practice `install.sh` fetches each once, so you won't notice. But it does mean
**a failed install cannot simply be re-run against the same token**: revoke it and
issue a new one. The public certificate (`/cert.pem`) is not a secret and stays
repeatable.

### Input validation

The server **name** and **connect address** are interpolated into a script that
runs as root on the target host, so they are validated on entry (no control
characters; addresses must be a plain hostname or IP) and shell-quoted on output.
The address reported back by `/complete` is validated the same way — it becomes a
URL this app connects to with credentials.

## Requirements

- **`PUBLIC_BASE_URL` must be reachable by the new server.** The install command and the
  script's callbacks are built from it, so set it to the externally reachable URL of the
  admin app (e.g. `https://dns-admin.example.com`), not `localhost`. See the
  [configuration reference](configuration.md).
- The target machine needs outbound access to the admin app and (for Docker installs) a
  working Docker runtime.
