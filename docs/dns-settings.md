# DNS settings

Beyond rewrites, AdGuard Admin can manage each server's **resolver configuration** —
the upstream DNS servers it forwards to, and per-domain **forward zones**. Manage both
from the **DNS Settings** page.

![DNS settings](images/dns-settings.png)

> **Opt-in per server.** Upstreams and forward zones are only applied to servers that
> have **Manage upstreams** enabled (set it on the [Servers](servers.md#per-server-options)
> page). Servers without it keep their own DNS config untouched.

## DNS servers (upstreams)

Each entry is one resolver address with a **kind** that maps to an AdGuard config field:

| Kind | AdGuard field | Purpose |
|---|---|---|
| **Upstream** | `upstream_dns` | The main resolvers queries are sent to |
| **Bootstrap** | `bootstrap_dns` | Plain resolvers used to look up the *hostnames* of encrypted upstreams |
| **Fallback** | `fallback_dns` | Used when the primary upstreams fail |
| **Private** | `local_ptr_upstreams` | Resolvers for private reverse-DNS (PTR) lookups |

Addresses accept any format AdGuard understands, including encrypted transports:

- Plain — `9.9.9.9`, `192.168.1.1`
- DoT (DNS-over-TLS) — `tls://1.1.1.1`
- DoH (DNS-over-HTTPS) — `https://dns.quad9.net/dns-query`
- DNSCrypt / `sdns://…`

Each entry has a [scope](concepts.md#scopes) (global / zone / server), so you can set a
fleet-wide default and override it for one zone or a single box.

## Forward zones (per-domain upstreams)

A forward zone routes **specific domains** to **specific upstreams** — classic
split-horizon DNS. For example, send everything under `cloud.internal` to your internal
resolver while the rest of the world keeps using your public upstreams.

Each forward zone has:

- **Domains** — one or more domain suffixes (e.g. `cloud.internal`, `home.lan`).
- **Forward to** — the upstream(s) those domains should use.
- **Scope** — global / zone / server, like upstreams.

## How it's applied

When a managed-upstreams server is [reconciled](concepts.md#reconciliation), the engine
computes the effective upstream + forward-zone config for that server (combining global,
zone, and server-scoped entries) and writes it via the AdGuard API. Changes land on the
next cycle, or immediately with **Sync now**.
