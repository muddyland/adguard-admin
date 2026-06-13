# Dashboard & query log

Two views give you fleet-wide visibility without logging into each server.

## Dashboard

The **Dashboard** combines counters and traffic metrics across the whole fleet.

![Dashboard](images/dashboard.png)

At the top, fleet counters: **zones**, **servers online**, **servers in sync**, and
total / global **DNS records**.

Below, **traffic metrics** aggregated from every reporting server:

- **DNS queries** and **blocked** counts, plus the **blocked rate**.
- **Average processing time**.
- A **per-server breakdown** so you can spot an outlier.
- **Top queried**, **top blocked**, and **top clients** lists.

Use the **zone** and **server** filters to focus on part of the fleet, and **Sync now**
to trigger an immediate [reconciliation](concepts.md#reconciliation) pass.

## Query log

The **Query Log** is a single, searchable stream merged from every selected server and
sorted by time — so you can answer "who asked for what, where, and was it blocked?"
without hopping between boxes.

![Query log](images/query-log.png)

Each row shows the **time**, **server**, **client** (a friendly name when AdGuard knows
one, otherwise the IP), **domain**, query **type**, **result** (`blocked` / `ok` /
`rewritten`), **answer**, **upstream**, and processing time. A **cached** badge marks
answers served from AdGuard's cache.

Controls:

- **Search** by domain or client (pushed down to each AdGuard instance).
- Filter by **zone**, **server**, and **result status** (blocked, filtered, allowed,
  rewritten, allowlisted, safe-search).
- Choose how many rows to pull per server (50–500).
- **Resizable columns** — drag a column edge; widths are remembered. **Reset columns**
  restores defaults.

Because the log is fetched live from each server's own query log, it reflects exactly
what AdGuard recorded — the admin app just merges, tags, and sorts it for you.
