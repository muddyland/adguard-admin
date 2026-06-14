# Filtering

AdGuard Admin manages each server's **filtering** centrally: the **blocklists** and
**allowlists** it subscribes to, and the **blocked services** (YouTube, TikTok, …) it
enforces. Define them once on the **Filtering** page and they're pushed to every server
in scope during [reconciliation](concepts.md#reconciliation).

> **Opt-in per server.** Filtering is only applied to servers that have **Manage
> filtering** enabled (set it on the [Servers](servers.md#per-server-options) page).
> Servers without it keep their own filtering config untouched.

## Blocklists

A blocklist is a subscription to a hosts/adblock-syntax list that AdGuard fetches and
keeps updated. Each entry has a **name**, a **URL**, an enabled toggle, and a
[scope](concepts.md#scopes) (global / zone / server).

You don't have to hunt for URLs — click **★ Add popular** to pick from a curated catalog
of well-known lists (AdGuard DNS filter, OISD, HaGeZi, StevenBlack, Peter Lowe's, URLHaus
and more). Recommended starters are flagged. Anything already added is shown as
**Added ✓**. You can still **+ Add blocklist** to paste any custom URL.

Toggling a list **off** keeps the subscription on the server but disables it — the same
as AdGuard's own enable/disable switch — rather than removing it.

## Allowlists

An allowlist (AdGuard's *whitelist filters*) exempts domains from blocking — useful for
fixing false positives without editing your blocklists. They work exactly like
blocklists: name, URL, scope, an enabled toggle, and a **★ Add popular** catalog.

## Blocked services

Blocked services are AdGuard's one-click bundles for whole platforms — block
**YouTube**, **TikTok**, **Facebook**, **Roblox**, etc. without knowing their domains.
Click **★ Add popular** to multi-select from the catalog, or **+ Add service** to enter
any valid AdGuard service id by hand.

The set of *enabled* blocked-service entries in a server's scope is pushed to AdGuard's
blocked-services list on sync.

## How it's applied

When a *manage-filtering* server is reconciled, the engine computes the effective set of
lists and services for that server (combining global, zone, and server-scoped entries)
and reconciles it against the server via the AdGuard API:

- **Lists missing** on the server are added; **enabled state** is corrected to match.
- **Blocked services** are merged into the server's set.
- The filtering engine itself is switched **on** if you've defined blocklists and it was
  off.

By default nothing is removed — admin-defined filtering coexists with whatever is already
on the box. Turn on **[Prune](concepts.md#prune)** for a server to make the admin app
authoritative: lists not defined here are removed, and the blocked-services set is
replaced with exactly the desired set.

Changes land on the next cycle, or immediately with **Sync now**.

## Importing existing filtering

Onboarding a server that already has lists configured? Use **Import filtering** from a
server's menu (or tick *Import this server's existing filtering on add*). It reads the
server's blocklists, allowlists and blocked services into the admin DB so the app becomes
the source of truth without losing what's there. Duplicates are skipped, so it's safe to
re-run.
