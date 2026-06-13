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
   - and **calls back** to register itself as a managed server.
4. The token flips from **pending** to **completed**, a new entry appears on the
   [Servers](servers.md) page, and the reconciliation engine starts pushing your
   [records](zones-and-records.md) and [settings](dns-settings.md) to it.

## Tokens

- Tokens are **single-use** and **expire** after `PROVISION_TOKEN_TTL_HOURS` (default 24).
- **Revoke** a token any time before it's used; revoked/expired tokens are rejected by
  the install endpoint.
- Toggle **Show revoked** to include inactive tokens in the list.

## Requirements

- **`PUBLIC_BASE_URL` must be reachable by the new server.** The install command and the
  script's callbacks are built from it, so set it to the externally reachable URL of the
  admin app (e.g. `https://dns-admin.example.com`), not `localhost`. See the
  [configuration reference](configuration.md).
- The target machine needs outbound access to the admin app and (for Docker installs) a
  working Docker runtime.
