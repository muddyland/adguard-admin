# Home Assistant

AdGuard Admin serves a subset of AdGuard Home's own `/control` API at its root, so
**Home Assistant's built-in [AdGuard Home integration][ha-integration] can point at
the admin app and treat your whole fleet as one AdGuard instance.**

Nothing to install on the Home Assistant side: it is the integration that ships
with Home Assistant, not a custom component, and it needs no HACS.

[ha-integration]: https://www.home-assistant.io/integrations/adguard/

## What you get

One device, with the entities the integration always creates:

| Entity | Reads |
|---|---|
| `sensor.dns_queries` | Total queries across the fleet |
| `sensor.dns_queries_blocked` | Total blocked |
| `sensor.dns_queries_blocked_ratio` | Blocked as a percentage of queries |
| `sensor.average_processing_speed` | Average response time, weighted by each server's query count |
| `sensor.rules_count` | Rules across the subscribed blocklists |
| `sensor.parental_control_blocked`, `sensor.safe_browsing_blocked`, `sensor.safe_searches_enforced` | The corresponding counters |
| `switch.protection`, `switch.filtering`, `switch.parental`, `switch.safe_browsing`, `switch.safe_search`, `switch.query_log` | Toggle that setting on every server in scope |

And the integration's services — `adguard.add_url`, `adguard.remove_url`,
`adguard.enable_url`, `adguard.disable_url` and `adguard.refresh` — for managing
filter-list subscriptions from an automation.

## Setup

**1. Create a local account for Home Assistant.** Any role works for the sensors;
the switches and services need **editor**. Use a dedicated account so you can see
which changes came from Home Assistant, and revoke it on its own.

> An OIDC-only account cannot be used. The AdGuard protocol authenticates with
> HTTP Basic on every request, which needs a local password — see
> [Users & SSO](users-and-sso.md).

**2. Add the integration.** In Home Assistant, *Settings → Devices & Services →
Add Integration → AdGuard Home*, then:

| Field | Value |
|---|---|
| Host | the admin app's hostname or IP |
| Port | the admin app's port (`8080` in the shipped compose file, **not** `3000`) |
| Username / Password | the account from step 1 |
| SSL | on if you reach the app over HTTPS |
| Verify SSL | off only if the app has a self-signed certificate |

That's it. Home Assistant calls `/control/status` to check the connection, and the
device appears with a software version of `AdGuard Admin <version>` — that is how
you can tell you reached the admin app rather than an AdGuard box.

Verified end to end against Home Assistant **2026.9.3**, which pins
`adguardhome==0.8.1` — every call that release's integration makes is exercised by
`backend/tests/test_ha_compat.py`. Note that 0.8.1 toggles protection with
`POST /control/dns_config`, while the library's unreleased successor uses
`POST /control/protection`; both are implemented, so a Home Assistant upgrade will
not break the switch.

## How the numbers are combined

Counters **add up**: queries, blocked queries and the per-service counters are the
fleet totals. The average processing time is weighted by each server's query
count, so a quiet box with one slow upstream cannot drag the figure around.

Switches read **on only when every reporting server has that setting on.** One
unprotected resolver therefore shows as `switch.protection` being off, rather than
disappearing behind a majority. A server that is unreachable does not vote, so a
box that is down cannot flip the switch by itself.

Filter lists are **merged by URL**, and `rules_count` takes the largest value
rather than the sum — the same subscription on five servers still holds the same
rules. A list that is switched off on one server reads as not enabled.

`sensor.rules_count` and the filtering switch therefore describe the fleet, not
any one box. For per-server numbers, use the [dashboard](dashboard-and-query-log.md),
which is built for exactly that.

## What the switches do and don't do

Flipping `switch.protection` applies it to every enabled server in scope **right
now**. It succeeds as long as at least one server took it; servers that were
unreachable are logged and skipped.

**These toggles are not part of the source of truth.** Protection, filtering,
safe browsing, parental control, safe search and the query log are not modelled in
the admin database, so [reconciliation](concepts.md) will not re-apply them: a
server that was offline when you flipped the switch keeps its old setting when it
comes back. If you need a setting to be *guaranteed* across the fleet, it belongs
in the app's own model — open an issue rather than relying on the switch.

Filter-list **subscriptions are different**, because the app does own those.
`adguard.add_url` writes a [filter list](filtering.md) into the admin database and
reconciliation pushes it out on its next cycle (within `SYNC_INTERVAL_SECONDS`,
60 s by default). Writing straight onto the servers would be worse than useless:
a server with [prune](concepts.md#prune) on would delete it again on the next pass.

Two consequences worth knowing:

- A subscription added this way only reaches servers with **Manage filtering**
  switched on — the same opt-in the UI uses. If no server in scope has it, the app
  records the list and logs a warning saying so.
- Only `http://` and `https://` list URLs are accepted. AdGuard also takes a local
  file path, but a path means something different on every server in a fleet.

## Updates are deliberately not offered

The integration normally creates an `update` entity with an *Install* button. Here
`/control/version.json` answers `{"disabled": true}`, which makes Home Assistant
skip creating it.

That is on purpose. AdGuard Admin already [manages the AdGuard Home installations
themselves](updates.md), one server at a time and inside a maintenance window,
because an upgrade restarts AdGuard and stops DNS resolution for everything behind
it. A second, unscheduled button that restarts every resolver in the fleet at once
is not a button worth having. Use the Updates page.

## Narrowing what Home Assistant sees

By default `/control` covers **every enabled server**. Set `HA_COMPAT_SCOPE` to
narrow it:

```env
HA_COMPAT_SCOPE=zone:iot-vlan      # only servers in that zone
HA_COMPAT_SCOPE=server:agh-1       # one server, by name or id
HA_COMPAT_SCOPE=fleet              # the default
```

This is the only way to narrow what Home Assistant sees, because its config flow
offers no base-path field and refuses a second entry for the same host and port.

For everything else — scripts, `curl`, a client that *does* let you set a base path
— the same API is also mounted per zone and per server, whatever `HA_COMPAT_SCOPE`
says:

```bash
curl -u ha-user:secret https://admin.example.com/control/status
curl -u ha-user:secret https://admin.example.com/zone/iot-vlan/control/status
curl -u ha-user:secret https://admin.example.com/server/agh-1/control/stats
```

Each response includes a non-standard `scope` field naming what it covered, plus
`servers_total` and `servers_reporting`, so you can tell a quiet fleet from an
unreachable one.

## Polling and caching

Home Assistant polls fourteen entities independently and seven of them read
`/control/stats`. Without a cache one poll cycle would fan out to the whole fleet a
dozen times over, so reads are held in memory for `HA_COMPAT_CACHE_SECONDS`
(15 s by default) and concurrent misses collapse into a single fan-out. Any write
clears the cache, so a switch reflects reality as soon as it is flipped.

Raise it if you have a large fleet and can live with staler numbers; set it to `0`
to disable caching entirely.

## Turning it off

```env
HA_COMPAT_ENABLED=false
```

Every `/control` path then answers `404`. The app logs which mode it is in at
startup, so you can confirm it from the container log:

```
AdGuard-compatible API enabled at /control (scope=fleet, cache=15s). Authenticated
with HTTP Basic against local accounts: viewer to read, editor to write.
```

## Security notes

- Authentication is **HTTP Basic against local accounts**, checked on every
  request against the database — disabling or demoting a user takes effect
  immediately. Reads need `viewer`, writes need `editor`.
- Failed attempts are rate-limited per client IP *and* per username, the same way
  the login endpoint is (`LOGIN_MAX_ATTEMPTS` and friends), and answer `429` with a
  `Retry-After` header. The budget is **separate** from the web UI's on purpose: a
  Home Assistant instance holding a stale password polls every 30 seconds, and a
  shared budget would lock you out of the UI at the same time.
- Basic auth sends the password on every request, so put the app behind HTTPS if
  Home Assistant reaches it over anything you do not control.
- A disabled account and a wrong password get the same `401`, so the endpoint
  cannot be used to enumerate which accounts exist.

## Endpoints

Everything below exists under `/control`, `/zone/{slug}/control` and
`/server/{id-or-name}/control`.

| Method | Path | Behaviour |
|---|---|---|
| `GET` | `/status` | Version, `protection_enabled` (ANDed), DNS addresses, plus `scope` / `servers_total` / `servers_reporting` |
| `GET` | `/stats` | Summed counters, weighted average time, merged top lists, element-wise summed series |
| `GET` | `/stats_info` | Longest statistics retention in scope |
| `GET` | `/filtering/status` | Merged blocklists and allowlists, ANDed `enabled`, union of user rules |
| `GET` | `/safebrowsing/status`, `/parental/status`, `/safesearch/status` | ANDed `enabled` |
| `GET` | `/querylog_info` | ANDed `enabled`, retention interval |
| `GET` | `/rewrite/list` | The **desired** rewrites for this scope, from the admin database |
| `POST` | `/protection` | `{enabled, duration?}` — fans out |
| `POST` | `/filtering/config`, `/querylog_config` | `{enabled, interval}` — fans out |
| `POST` | `/safebrowsing/enable`\|`disable`, `/parental/…`, `/safesearch/…` | Fans out |
| `POST` | `/filtering/refresh?force=` | Fans out; returns the total number of lists updated |
| `POST` | `/filtering/add_url`, `/remove_url`, `/set_url` | Writes a filter list to the admin database |
| `POST` | `/rewrite/add`, `/rewrite/delete` | Writes a DNS record to the admin database |
| `POST` | `/version.json` | Always `{"disabled": true}` |
| `POST` | `/update` | `501` — see [Updates](updates.md) |

A `/control` path that is not in this list answers `404`, never the SPA's HTML.

## Troubleshooting

**"Failed to connect" in the config flow.** It calls `GET /control/status`. Check
the port (the admin app's, not AdGuard's `3000`), and check the credentials — a bad
password is a `401`, which the flow also reports as a connection failure. `curl -u`
against `/control/status` tells you which it was.

**Everything reads zero, and `switch.protection` is off.** `servers_reporting` in
`/control/status` is `0`: the admin app cannot reach any AdGuard box. That is a
fleet problem, not a Home Assistant one — see the Servers page.

**A switch flips back on the next poll.** Something else is setting it — most
likely one server was unreachable when the write went out, and the AND across the
fleet now reads it as off. The app logs which servers a write failed on.

**`adguard.add_url` seems to do nothing.** Either no server in scope has *Manage
filtering* on (the app logs a warning saying exactly that), or reconciliation has
not run yet — give it `SYNC_INTERVAL_SECONDS`. The list appears on the Filtering
page immediately either way.

**No update entity.** That is intended; see above.
