# Zones & DNS records

## Zones

Create and manage zones from the **Zones** page.

![Zones](images/zones.png)

Each zone has:

- **Name** — display name (`Home`, `Cloud`, `IoT VLAN`).
- **Slug** — short identifier shown as a colored badge across the app (auto-derived from
  the name if you leave it blank).
- **Description** — free text to remind future-you what the zone is for.

The list shows how many **servers** and **records** each zone contains. Deleting a zone
is blocked while servers still reference it — move or remove those servers first.

See [Core concepts → Zones](concepts.md#zones) for how zones drive scoping and filtering.

## DNS records

DNS records are **rewrites** — a domain mapped to an answer (an IP, or another hostname
for a CNAME-style rewrite). Manage them from the **DNS Records** page.

![DNS records](images/records.png)

Each record has:

- **Domain** — the name to rewrite. AdGuard wildcards like `*.lan` are supported.
- **Answer** — the IP address (`192.168.1.10`) or hostname to return.
- **Scope** — `global` or `zone` (see [scopes](concepts.md#scopes)).
- **Zone(s)** — which zone(s) a zone-scoped record applies to (a record can target more
  than one zone).
- **Description** — optional note.
- **Enabled** — disable a record to stop pushing it without deleting it. On the next
  reconcile, a disabled record is treated as "not desired."

### How records reach your servers

When you add, edit, disable, or delete a record, the change is applied on the next
[reconciliation](concepts.md#reconciliation) cycle (default 60s). To apply immediately,
use **Sync now**.

- **Adding/enabling** a record pushes it to every server in scope.
- **Disabling/deleting** a record removes it from servers in scope **only if those
  servers have [prune](concepts.md#prune) enabled.** With prune off, the app stops
  managing the record but leaves the existing rewrite in place on the server.

### Managed vs. imported records

Records the app generates automatically (for example, a global rewrite mapping each
managed server's own hostname to its IP, so servers can resolve each other) are marked
**managed** and are maintained by the engine — you don't edit those by hand.

You can also pull a server's *existing* rewrites into the admin DB with
[import](servers.md#importing-existing-config), which is the easy way to adopt a server
that already has records.

### Filtering

Use the search box to filter by domain or answer, and the scope/zone dropdowns to narrow
the list — useful once you have hundreds of records across many zones.
