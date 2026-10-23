# Observability

The control plane keeps its own record of how the fleet is doing, so the UI
never has to ask every server on each page load, history is available, and
anything that already speaks Prometheus can scrape the whole fleet from one
place.

## The sample store

Every reconcile cycle (`SYNC_INTERVAL_SECONDS`, 60 s by default) the
collector stores one row per enabled **server**, **host agent** and **load
balancer** in the application's own database:

| Entity | Stored each cycle |
|---|---|
| Server | online, in sync, queries and blocked in AdGuard's statistics window, average processing time, **queries/s** and **blocked/s** derived from the previous sample |
| Host | online, load averages, memory and disk usage, managed services not running, days until the agent certificate expires |
| Balancer | online, in sync, VIP owner, director (ipvs), backends up and known, **queries/s** through the balancer, dnsdist cache hit ratio |

Rates are computed at collection time from AdGuard's current-hour bucket
(dnsdist's and IPVS's counters for balancers), with resets handled, so a
reader never has to difference counters. Alongside the samples each server
keeps a **snapshot** of its last `/control/stats` answer: the window totals
and the top queried, blocked and client lists the Traffic page shows.

Retention: raw per-cycle samples are kept for `METRICS_RETENTION_DAYS`
(7); once an hour they are rolled up into hourly means kept for
`METRICS_ROLLUP_RETENTION_DAYS` (90). Both prune automatically. With ten
entities at a one-minute cycle that is about 15,000 rows a day, a few
megabytes a week in SQLite.

The store feeds:

- the **Dashboard**: the needs-attention list, fleet and zone tiles, and the
  traffic curve;
- the **Traffic** page: the curve with range and filters, per-server totals
  and top lists;
- `GET /metrics` for **Prometheus**.

`METRICS_ENABLED=false` switches the collector off; the Dashboard and Traffic
pages then show no numbers.

## Prometheus

Set `METRICS_TOKEN` to a long random string and point Prometheus at the
control plane. Nothing runs on the hosts: the control plane already holds an
mTLS channel to every agent and talks to every server once a minute, so it is
the one place that knows the whole fleet. Scraping it rather than pushing
from agents keeps the agents pull-only, needs no second secret on every host
and no Pushgateway.

```yaml
scrape_configs:
  - job_name: adguard-admin
    scheme: https
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials: <METRICS_TOKEN>
    static_configs:
      - targets: ["adguard-admin.example.com"]
```

A scrape every 60 s matches the collection interval; faster scrapes return
the same sample. All metrics are gauges with the `adguard_admin_` prefix.

| Metric | Labels | Meaning |
|---|---|---|
| `server_up`, `server_in_sync`, `server_update_available` | `server`, `zone` | state from the last reconcile |
| `server_queries_per_second`, `server_blocked_per_second` | `server`, `zone` | rates from the last two samples |
| `server_queries_window`, `server_blocked_window` | `server`, `zone` | AdGuard's statistics window totals |
| `server_processing_milliseconds` | `server`, `zone` | average processing time AdGuard reports |
| `server_sample_age_seconds` | `server`, `zone` | how old the newest sample is |
| `server_info` | `server`, `zone`, `version`, `enabled` | always 1 |
| `agent_up`, `agent_load1`, `agent_memory_used_ratio`, `agent_disk_used_ratio`, `agent_services_down` | `host`, `zone` | host health from the agent |
| `agent_cert_expiry_timestamp_seconds` | `host`, `zone` | alert on `… - time() < 30*86400` |
| `agent_info` | `host`, `zone`, `version`, `arch`, `os` | always 1 |
| `balancer_up`, `balancer_in_sync`, `balancer_vip_owner`, `balancer_director` | `balancer`, `zone`, `mode`, `host` | balancer state; `director` is 0 on an ipvs standby |
| `balancer_backends_up`, `balancer_backends_total`, `balancer_queries_per_second`, `balancer_cache_hit_ratio` | `balancer`, `zone`, `mode`, `host` | what the balancer sees |
| `balancer_backend_up`, `balancer_backend_queries_per_second` | plus `backend` | per backend, as the balancer reports it |
| `fleet_servers`, `fleet_servers_online`, `fleet_agents_online`, `fleet_last_sync_timestamp_seconds` | | fleet totals |

Alerting ideas: `adguard_admin_server_up == 0`, `sum by (zone)
(adguard_admin_balancer_vip_owner) == 0` for a zone with a VIP,
`adguard_admin_balancer_backends_up < adguard_admin_balancer_backends_total`,
`time() - adguard_admin_fleet_last_sync_timestamp_seconds > 300`.

## Needs attention

The Dashboard's first card lists everything currently wrong, worst first:
servers offline or in error, configuration drift, cooldowns and failed
updates; hosts unreachable, certificates expiring within 30 days, failed
self-updates, disks over 90 percent; balancers offline, drifted, with
backends down, or a VIP owner with no IPVS virtual server; a zone whose VIP
nobody holds; and a reconcile loop that has not finished in three intervals.
An empty list reads "All clear". The same list is available at
`GET /api/metrics/attention`.
