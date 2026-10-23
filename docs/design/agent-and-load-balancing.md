# Design: a managed-host agent, and dnsdist load balancing

*Status: implemented 2026-10-23 (agent, control plane, UI). Kept as the design
record; the exact interfaces are in [agent-api.md](agent-api.md) and the user
guides are [hosts.md](../hosts.md) and [load-balancing.md](../load-balancing.md).
One assumption below turned out wrong and is corrected inline: AdGuard Home does
not use an incoming ECS option to identify clients.*

## The problem

Clients configured with a primary and a secondary resolver do not spread load.
Most stacks send everything to the first entry and only fall over on timeout, so
one AdGuard Home box carries most of a zone's queries and the others idle. When
that box stalls, every client stalls with it.

The fix is a single virtual IP per zone that balances across the zone's servers
and ejects an unhealthy one within seconds. AdGuard Admin should set that up and
keep it in sync the same way it keeps DNS records in sync: declare it once, let
reconciliation converge it, show its state in the UI.

## What this design adds

1. **An on-box agent.** One small daemon per managed host, reachable only over
   mutual TLS. It fronts whatever runs on that host: AdGuard Home, dnsdist, or
   both. The control plane talks to the agent; the agent talks to local services
   on loopback.
2. **dnsdist as the balancer.** A purpose-built DNS proxy with active health
   checks, UDP and TCP, per-backend statistics and a local REST API. The agent
   installs it, renders its config from the control plane's desired state, and
   relays its statistics back.
3. **keepalived for the virtual IP.** Two or more hosts in a zone share one VRRP
   address, so the balancer itself is not a single point of failure.
4. **A Load balancers page.** Backends, health, query share, latency, drops,
   who currently owns the VIP, plus drain and restart actions.

### Recommended topology: every zone server runs both roles

```
                 clients -> 10.0.0.53 (zone VIP, VRRP)
                                 |
           +---------------------+---------------------+
           |                     |                     |
     host A (agent)        host B (agent)        host C (agent)
     dnsdist :53           dnsdist :53           dnsdist :53
     keepalived prio 150   keepalived prio 100   keepalived prio 50
     AdGuard 127.0.0.1:5335  AdGuard 127.0.0.1:5335  AdGuard 127.0.0.1:5335
           \__________________ backends: A, B, C __________________/
```

No extra machines. Whichever host holds the VIP balances across all three
AdGuard instances, including the ones on the other hosts. If it dies, VRRP moves
the VIP in about a second and the next host's dnsdist takes over with the same
backend list. A "dedicated LB host" topology is the same design with the AdGuard
role switched off on the LB hosts, and is supported but not the default.

AdGuard moves off port 53 on these hosts and listens on loopback only. dnsdist
owns :53 on every host address and on the VIP.

## Part 1: the agent

### Why an agent at all

Today the control plane has exactly one channel to a box: AdGuard Home's HTTP
API. That is why the updater for Docker hosts is a shell script on a timer and
why a container upgrade can only be observed, never driven. dnsdist has no
remote configuration API that is safe to expose, and keepalived has none at all.
Every feature in this document needs something on the box that can write a
config file and restart a service. Once that exists, it should also carry the
AdGuard traffic, so there is one well-secured channel instead of several ad hoc
ones.

### Shape

- A single static binary, `adguard-admin-agent`, written in Go. It runs as a
  systemd service on bare metal and as a container with the Docker socket on
  Docker hosts. The reason for Go rather than Python is purely deployment: a
  dependency-free binary that works on a box with no Python and inside a scratch
  image, with mTLS server and client in the standard library. Everything else in
  the repo stays Python and Vue.
- Listens on one port (default 8443) with TLS and **requires a client
  certificate** signed by the control plane's CA. There is no plaintext
  listener and no other authentication path.
- Roles are enabled per host: `adguard`, `dnsdist`. A role is a module inside
  the one binary, not a separate install.
- The control plane connects to the agent (push model), exactly as it connects
  to AdGuard today. The reconcile loop, `fan_out` and the fleet status
  bookkeeping keep their current shape. The agent never needs an inbound route to
  the control plane after enrollment.

### Agent API (mTLS only)

| Method and path | Purpose |
|---|---|
| `GET /v1/info` | Agent version, enabled roles, OS, arch, Docker present, service versions. |
| `GET /v1/health` | Load, memory, disk free under the data directories, container or unit state per role. This is what explains a "freeze" instead of just hiding it. |
| `ANY /v1/adguard/*` | Reverse proxy to the local AdGuard API on loopback. The control plane keeps sending AdGuard's Basic auth header; the agent adds nothing and strips nothing. The existing UI embed in `routers/proxy.py` works through this path unchanged. |
| `POST /v1/adguard/update` | Pull image and recreate the container, or run AdGuard's self-update on bare metal. Replaces the shell updater and its timer. Reports progress; the control plane's existing "wait for new version" poll stays. |
| `PUT /v1/dnsdist/config` | Desired state as JSON (below). Agent renders the Lua config, validates it with `dnsdist --check-config`, applies it, and returns the hash it is now running. Idempotent. |
| `GET /v1/dnsdist/state` | Backends, pools, frontends and global counters, read from dnsdist's local REST API and normalised. |
| `POST /v1/dnsdist/backends/{name}/drain` and `/undrain` | Take a backend out of rotation without removing it from the config (dnsdist `setDown` / `setAuto`). |
| `PUT /v1/keepalived/config` | VIP, priority, interface, peers, auth secret. Same render, check, apply pattern. |
| `GET /v1/keepalived/state` | Whether this host currently holds the VIP. |
| `POST /v1/services/{name}/restart` | Restart `dnsdist`, `keepalived` or `adguard`. |
| `GET /v1/logs?service=dnsdist&lines=200` | Tail of a service log, for the UI. |
| `POST /v1/cert/renew` | Returns a CSR for a fresh key; the control plane signs it and installs the result with `PUT /v1/cert`. |

All local secrets (dnsdist API key, console key, keepalived auth pass) are
generated by the agent on first run, stored under `/etc/adguard-admin-agent/`
mode 0600, and never leave the host. dnsdist's web server and console bind to
127.0.0.1 only.

### Enrollment and PKI

The control plane gets a CA, generated on first start and stored in the database
with the key Fernet-encrypted, like server passwords today. It issues two kinds
of certificate:

- **Agent certificates** with `extendedKeyUsage = serverAuth` and a SAN of the
  agent's connect address. One year lifetime.
- **One client certificate** for the control plane itself with
  `extendedKeyUsage = clientAuth`, CN `adguard-admin`.

The EKU split matters: an agent certificate cannot be used to impersonate the
control plane to another agent, so a compromised host gains nothing against the
rest of the fleet.

Enrollment during provisioning:

1. The install script downloads the agent binary and starts it with the
   provisioning token.
2. The agent generates its key locally and sends a CSR to
   `POST /api/provision/{token}/csr`.
3. The control plane signs it, returns the certificate plus the CA certificate,
   records an `Agent` row, and marks the token consumed. The token is single use
   and expires, as now.
4. The agent verifies every later connection against the CA and, for belt and
   braces, checks the client CN. The control plane verifies the agent against
   the same CA and the SAN. The per-server pinned `tls_cert` column becomes
   unnecessary for agent-managed hosts.

The private key never crosses the network. Renewal is driven by the control
plane on its normal schedule when a certificate is inside its last third, so
nothing on the box needs a credential to call home.

### Data model

```
Agent
  id, name, url (https://host:8443), zone_id
  cert_pem, cert_expires_at, roles (adguard, dnsdist)
  version, os, arch, last_seen, last_error, health (json snapshot)

Server            (existing)   + agent_id nullable
                               + dns_address, dns_port   (what a balancer should hit)

LoadBalancer
  id, name, zone_id, agent_id, enabled
  listen_addresses (json)        e.g. ["0.0.0.0:53"]
  policy                         leastOutstanding | roundrobin | wrandom | firstAvailable
  ecs                            bool, default true
  cache_enabled, cache_max_entries
  healthcheck_name, healthcheck_interval_s, healthcheck_max_failures, healthcheck_rise
  acl (json)                     client ranges allowed to query
  vip, vip_interface, vrrp_priority, vrrp_router_id   (nullable: no VIP)
  desired_hash, applied_hash, in_sync, status, last_synced, last_error

LoadBalancerBackend             (optional per-backend overrides; absent = defaults)
  load_balancer_id, server_id, enabled, weight, order

AgentCA (singleton)
  cert_pem, key_enc, client_cert_pem, client_key_enc
```

Backends default to "every enabled AdGuard server in the balancer's zone", so
adding a server to a zone adds it to that zone's balancers on the next reconcile
pass. Overrides exist for weight (uneven hardware) and to pin a server out.

Servers and balancers both hang off an `Agent`, which is what makes the
co-located topology one row per host rather than two unrelated installs.

### Reconciliation

`sync.py` gains a second phase after servers. For each enabled balancer:

1. Build the desired config from the zone's servers, the balancer row and any
   overrides. Serialise it canonically and hash it.
2. If the hash equals `applied_hash` and the agent's last reported hash, do
   nothing except refresh state.
3. Otherwise `PUT /v1/dnsdist/config` (and keepalived if a VIP is set). Store
   the returned hash. Mark `in_sync`.
4. `GET /v1/dnsdist/state` every pass. Store the per-backend snapshot on the
   balancer and copy each backend's up/down into a new `Server.lb_state`
   column, so the Servers page shows "dnsdist marked this server down" next to
   the control plane's own view of it.

The same lock, cooldown and concurrency rules as server reconciliation apply.
Running the balancer phase second is deliberate: a newly provisioned server
enters the pool in the same pass that first reconciles it.

Desired-state JSON the agent receives (the agent owns the Lua rendering, so the
control plane never generates code that runs as root):

```json
{
  "listen": ["0.0.0.0:53"],
  "policy": "leastOutstanding",
  "ecs": true,
  "cache": {"enabled": false},
  "healthcheck": {"name": "a.root-servers.net.", "interval_s": 1, "max_failures": 3, "rise": 2},
  "acl": ["10.0.0.0/8", "192.168.0.0/16", "127.0.0.0/8"],
  "backends": [
    {"name": "dns-a", "address": "127.0.0.1", "port": 5335, "weight": 1, "order": 1},
    {"name": "dns-b", "address": "10.0.0.12", "port": 5335, "weight": 1, "order": 1}
  ]
}
```

Rendered on the box, roughly:

```lua
setLocal("0.0.0.0:53")
setACL({"10.0.0.0/8", "192.168.0.0/16", "127.0.0.0/8"})
newServer({name="dns-a", address="127.0.0.1:5335", useClientSubnet=true, checkName="a.root-servers.net.", checkInterval=1, maxCheckFailures=3, rise=2})
newServer({name="dns-b", address="10.0.0.12:5335", useClientSubnet=true, checkName="a.root-servers.net.", checkInterval=1, maxCheckFailures=3, rise=2})
setServerPolicy(leastOutstanding)
webserver("127.0.0.1:8083")
setWebserverConfig({apiKey=os.getenv("DNSDIST_API_KEY")})
controlSocket("127.0.0.1:5199")
setKey(os.getenv("DNSDIST_CONSOLE_KEY"))
```

Apply strategy: first version renders, checks and restarts dnsdist. A restart
takes well under a second and clients retry, and with a VIP the restart can be
ordered so the VIP owner goes last. A later version can apply backend changes
live through the console (`newServer` / `rmServer`) and reserve restarts for
listener or policy changes.

### Two AdGuard details the balancer depends on

**Client identity.** Behind any proxy AdGuard sees the balancer's address as
the client. dnsdist adds an EDNS Client Subnet option carrying the real client
address when `useClientSubnet` is on, and AdGuard Home shows that in the query
log's request details and forwards it upstream, but **it does not use it to
identify clients** (checked against AdGuard Home's changelog: the only ECS
features are a custom outgoing ECS address and the request-details display).
So per-client rules and client names in AdGuard do not apply to proxied
traffic. The design accepts this and documents it; dnsdist's PROXY protocol is
not an option because AdGuard Home does not accept it. A source-preserving
alternative for later is keepalived's IPVS in direct-routing mode, at the cost
of dnsdist's statistics and policies.

**Port 53 on a shared host.** dnsdist needs :53. On a co-located host the agent
moves AdGuard to 127.0.0.1:5335: a Docker install republishes the container's
DNS port to loopback, a bare-metal install gets `dns.bind_hosts` and `dns.port`
edited in `AdGuardHome.yaml` and a restart. `Server.dns_address` and
`Server.dns_port` record the result so the balancer config is derived, not
typed.

### Caching

Off by default. AdGuard already caches, and a cache in front of it would make
AdGuard's statistics undercount and could serve a block decision after the rule
changed. It is a per-balancer switch for anyone who wants it.

## Part 2: the UI

**Load balancers** page, editor and above:

- Table: name, zone, VIP and current owner, status, backends up/down, total
  QPS, in sync.
- Detail: backends table with state, QPS, queries, drops, latency, outstanding,
  weight and a share bar (queries as a percentage of the balancer's total, which
  is the direct answer to "is it balanced"), frontends, cache hit rate if
  enabled, health check settings, last error.
- Actions per backend: drain, undrain, set weight. Per balancer: restart
  dnsdist, re-sync now, show log.
- Create or edit: zone, agent, listen addresses, policy, ECS, cache, health
  check, ACL, VIP and priority.

**Servers** page gains a column for the balancer's view of the server (up,
down, draining) and the agent's host health.

**Provisioning** gains role checkboxes (AdGuard, dnsdist) and, when dnsdist is
ticked, the balancer fields. The generated one-liner is unchanged in shape.

**Dashboard** gains a tile per zone VIP: owner, QPS, backends up.

**Updates** shows agent-managed Docker servers as upgradeable from the UI
rather than "on-box updater".

Statistics are polled by the control plane on the sync interval and cached, like
the Home Assistant compatibility layer does. dnsdist reports per-backend QPS
itself, so the UI does not have to compute rates. A small ring of samples (24 h)
for sparklines is a later addition.

## Part 3: what the agent fixes in the current method

The user asked for an honest look at the current provisioning and update path.
These are the weak points, and what changes.

| Today | Risk | With the agent |
|---|---|---|
| `install.sh` fetches `/config` and runs `eval` on it as root. | A control-plane bug or a malicious record in the database becomes root code on every new box. Values are shell-quoted, which is the right mitigation, but the design still turns data into code. | The agent reads JSON. Nothing from the control plane is executed as a shell string after bootstrap. |
| The TLS private key is generated on the control plane and downloaded over a token URL. | Single-fetch limits replay, but the key still transits the network and sits briefly in a log-visible URL flow. | CSR enrollment. The key is generated on the box and never leaves it. |
| Without SSL, AdGuard's admin API and Basic credentials travel in clear text across the LAN on every reconcile pass. | Anyone on the segment can read the AdGuard admin password. | All control-plane traffic goes to the agent over mTLS. AdGuard's own API can stay bound to loopback. |
| With SSL, AdGuard's API is exposed on the LAN protected only by Basic auth, and AdGuard rate-limits bad logins. | A scan can lock the control plane out of its own server (the `cooldown_until` logic exists because of this). | AdGuard's API is reachable only through the agent, which requires a client certificate before any request reaches it. |
| The Docker updater is a bash script on a timer with no feedback channel. | A failed or half-done upgrade is only noticed when the version stops changing. Compose-managed containers and plain `docker run` need different code paths in shell. | Upgrade is a request with a response. Progress and errors come back to the control plane in the same pass. |
| `PUBLIC_BASE_URL` can be plain HTTP, and the bootstrap trusts whatever answers. | The one-time token and the generated admin password are readable on the wire during install. | Still a bootstrap weakness. Mitigation: the install one-liner can embed the CA fingerprint so the agent pins the control plane during enrollment even when the operator has not set up TLS in front of it. Recommend requiring HTTPS for `PUBLIC_BASE_URL` once the agent exists. |
| The embedded AdGuard UI runs a managed server's JavaScript inside the admin origin (documented trust decision in `routers/proxy.py`). | A compromised server can read the admin session. | Unchanged by this design. Routing it through the agent does not alter the origin problem. The fix remains a second hostname. |

The agent is itself a root-level remote control on every host, so the design
is only as safe as the CA. The CA key is Fernet-encrypted at rest with the same
`FERNET_KEY` that already protects every server password, which is no change in
blast radius: whoever has the database and that key already owns the fleet.

## Part 4: plan

| Phase | Deliverable | Proves |
|---|---|---|
| 0, spike | Hand-written dnsdist on one host in front of the existing three servers, clients pointed at it for a day. | ECS client identification works. The freeze is masked. Which `health` numbers would have predicted it. |
| 1 | Agent binary with `info`, `health`, `adguard` proxy, `cert`. CA and `Agent` table, CSR enrollment, provisioning installs the agent, `AdGuardClient` can target an agent with the client cert. | mTLS channel end to end. Existing reconcile works through the agent. |
| 2 | dnsdist role: `LoadBalancer` model, desired-state builder, reconcile phase, agent config and state endpoints, Load balancers page. | A zone converges onto a balancer and the UI shows the balance. |
| 3 | keepalived role, VIP fields, co-located port move, VIP owner in the UI. | Two hosts, one address, failover. |
| 4 | Docker upgrades through the agent, drain and restart actions, dashboard tile, sample history, docs. | Polish. |

Phase 0 is a day and should be done first regardless, because its result
decides whether phase 2 renders `useClientSubnet` or has to find another way to
carry client identity.

## Out of scope

- DNS-over-TLS or DNS-over-HTTPS on the balancer. dnsdist can do both; the
  fleet's clients are LAN clients on plain DNS.
- Anycast or ECMP. VRRP is enough for a LAN and needs no routing changes.
- Replacing the agent's push model with an outbound connection from the agent.
  Worth revisiting if a zone ever sits behind NAT with no inbound route; the API
  above would not change, only the transport.
