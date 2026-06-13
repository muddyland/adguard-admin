# Core concepts

Understanding these five ideas explains everything else in the app.

## Source of truth

The **admin database is the source of truth** for the DNS records and settings it
manages. You declare *desired state* in the UI; the app makes each server match it.

This is the opposite of editing servers by hand. You never wonder "which box has which
record?" — you define it once and the fleet converges.

Crucially, the app only owns what it created. Records and settings already present on a
server that the app didn't add are left alone — unless you turn on [prune](#prune).

## Zones

A **zone** is a logical group of servers — `home`, `cloud`, `iot-vlan`, `branch-office`.

Zones do two jobs:

- They're the unit you **scope records and settings to** (see below).
- They're a **filter** everywhere — dashboard metrics, the query log, and server lists
  can all be narrowed to a single zone.

A zone can have zero servers (handy when planning) and a server belongs to at most one
zone.

![Zones](images/zones.png)

## Scopes

Every DNS record and DNS setting has a **scope** that decides *which servers it applies
to*:

| Scope | Applies to | Use it for |
|---|---|---|
| **Global** | Every enabled server in every zone | Records true everywhere (`nas.lan`, company-wide split-horizon) |
| **Zone** | Servers in the selected zone(s) | Site-specific records (`printer.branch.lan`) |
| **Server** | A single server *(DNS settings only)* | One-off upstream overrides |

For a given server, its **desired record set** is:

```
desired(server) = { enabled global records } ∪ { enabled records in server's zone }
```

![DNS records with scope badges](images/records.png)

## Reconciliation

A background loop (default every `SYNC_INTERVAL_SECONDS = 60`) does this for each
enabled server:

1. Read the server's current DNS rewrites via the AdGuard API (`/control/rewrite/list`).
2. Compute the desired set for that server (global ∪ zone records).
3. **Add** anything missing.
4. **Remove** anything that shouldn't be there — *only if [prune](#prune) is on*.
5. If the server also has *Manage upstreams* enabled, apply [DNS settings](dns-settings.md) too.

Offline servers don't block anything — they're simply retried on the next cycle until
they converge. You can also force an immediate pass with **Sync now** (whole fleet) or
per-server from the Servers page.

> A short cooldown is applied after repeated failures so a dead box doesn't get hammered.

## Prune

**Prune controls deletion.** It's **off by default** and configurable per server.

- **Prune off** (default): the engine only *adds* missing records. Anything else on the
  server — including records you created by hand directly in AdGuard — is never touched.
  Safe, non-destructive.
- **Prune on**: the engine also *removes* rewrites that aren't in the desired set, making
  the server an exact mirror of the admin DB. Turn this on when you want the app to be
  the *only* thing managing a server's rewrites.

Because prune is opt-in, adopting AdGuard Admin for an existing server is safe: it won't
delete a thing until you ask it to.
