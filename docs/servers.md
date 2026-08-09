# Servers

The **Servers** page is your fleet at a glance: status, AdGuard version, sync state, and
which zone each box belongs to.

![Servers](images/servers.png)

## Adding an existing server

**Servers → + Add server**, then provide:

- **Name** — a friendly label (`living-room-pi`, `hetzner-vps`).
- **URL** — the AdGuard Home admin URL, e.g. `http://192.168.1.2:3000` or
  `https://dns.example.com`.
- **Username / password** — the server's AdGuard admin credentials. The password is
  **encrypted at rest** with your `FERNET_KEY` and never returned to the browser.
- **Zone** — which [zone](concepts.md#zones) this server joins.
- **Options** — *Enabled*, *Prune*, *Manage upstreams* (see below).

Use **Test** to probe connectivity and credentials before saving. Once saved and
reachable, the server flips to **online** and starts receiving the desired state.

**Show credentials** decrypts and displays the stored password. It is
**admin-only** and every use is written to the audit log — an editor can already
*use* the credential through the embedded UI, but extracting the plaintext is a
separate, higher-privilege act.

### Embedded UI

**Open UI (embedded)** proxies the server's own AdGuard interface into a modal.
Those bytes come from the remote instance but run in this app's origin, because
AdGuard's UI needs `localStorage` and `document.cookie` and so cannot be
sandboxed into an opaque origin. Embedding a server therefore means trusting it
with your admin session — see
[the trust note](configuration.md#embedded-adguard-ui-proxy). Use
*Open UI in new tab*, or `UI_PROXY_ENABLED=false`, if you would rather not.

The UI session is authorized by a short-lived cookie whose user is re-checked on
every request, so disabling or demoting an account revokes embedded access
immediately.

> Starting from scratch with no AdGuard Home installed yet? Use
> [Provisioning](provisioning.md) instead — it installs and registers the server for you.

## Status & sync columns

- **Status** — `online`, `offline`, `error`, or `unknown`, based on the last contact.
- **Version** — the AdGuard Home version reported by the server; an *update available*
  hint appears when a newer release exists.
- **Sync** — whether the server's rewrites currently match the desired state.
- **Last synced** — when the engine last reconciled this server.

## Per-server options

| Option | Effect |
|---|---|
| **Enabled** | When off, the server is ignored by the reconciliation engine (no pushes, no metrics). |
| **Prune** | When on, the engine *removes* rewrites that aren't in the desired set, mirroring the admin DB exactly. Off by default — see [prune](concepts.md#prune). |
| **Manage upstreams** | When on, the server also receives [DNS settings](dns-settings.md) (upstream resolvers and forward zones). When off, the server keeps its own DNS config. |
| **Manage filtering** | When on, the server also receives [filtering](filtering.md) (blocklists, allowlists and blocked services). When off, the server keeps its own filtering config. |

## Importing existing config

Adopting a server that already has records, upstreams, or filtering? Use **import** (from
the server's row menu):

- **Import records** pulls the server's existing DNS rewrites into the admin DB so they
  become managed going forward.
- **Import settings** pulls the server's upstream/forward-zone configuration in.
- **Import filtering** pulls the server's blocklists, allowlists and blocked services in.

This lets you onboard a hand-configured server without retyping everything — and without
risking deletion, since [prune](concepts.md#prune) stays off until you enable it.

## Per-server sync & the AdGuard UI

Each server row lets you **sync just that server** on demand and **Open UI** to jump
straight into that box's native AdGuard Home interface when you need something the fleet
manager doesn't cover.
