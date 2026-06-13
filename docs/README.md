# AdGuard Admin — Documentation

AdGuard Admin is a **fleet manager for [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome)**.
Instead of logging into each AdGuard box one by one, you define your DNS records and
settings *once* in a single control plane and let the reconciliation engine push them
out to every server — and keep them that way.

![Walkthrough](images/walkthrough.gif)

## Guides

| Guide | What it covers |
|---|---|
| [Getting started](getting-started.md) | Run the app with Docker, log in, add your first server |
| [Core concepts](concepts.md) | Source-of-truth model, zones, scopes, reconciliation, prune |
| [Zones & DNS records](zones-and-records.md) | Grouping servers and managing rewrites |
| [Servers](servers.md) | Adding, testing, importing, and tuning per-server behavior |
| [DNS settings](dns-settings.md) | Upstream resolvers and per-domain forward zones |
| [Provisioning](provisioning.md) | One-line install of brand-new AdGuard servers |
| [Dashboard & query log](dashboard-and-query-log.md) | Fleet-wide metrics and a combined, searchable query log |
| [Users & SSO](users-and-sso.md) | Roles (admin/editor/viewer) and OIDC / Authentik login |
| [Configuration reference](configuration.md) | Every environment variable |

## The 30-second version

1. **Group** your AdGuard servers into [zones](concepts.md#zones) (`home`, `cloud`, `iot`…).
2. **Define** DNS records once — [globally](concepts.md#scopes) or scoped to a zone.
3. The **reconciliation engine** diffs desired vs. actual state on each server and
   applies the difference, retrying offline servers until they converge.
4. Watch it all from one **dashboard** and a combined **query log**.

> The admin database is the **source of truth**. Records you manage here are owned by
> the app; everything else on your servers is left untouched unless you explicitly opt
> into [prune](concepts.md#prune).
