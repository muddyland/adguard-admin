# Contract: agent, control-plane API and UI

*Companion to [agent-and-load-balancing.md](agent-and-load-balancing.md). This file is
the exact interface the Go agent, the Python backend and the Vue frontend are
built against. When the three disagree, this file wins; change it first.*

## 1. Conventions

- All bodies are JSON. Errors are `{"error": "<message>"}` with a 4xx/5xx status
  (agent) or FastAPI's `{"detail": "..."}` (control plane).
- Unknown fields in a spec are ignored by the agent. Missing optional fields take
  the defaults listed here.
- **Spec hash** = lowercase hex SHA-256 of the *canonical JSON* of the spec.
  Canonical JSON: object keys sorted bytewise, no whitespace, UTF-8, no
  float-looking integers (`3`, never `3.0`). Python:
  `json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
  Go: decode with `UseNumber`, re-encode with sorted keys and no whitespace. Specs
  contain only strings, integers, booleans, arrays and objects, never floats.
- Timestamps are RFC 3339 UTC strings.
- The agent listens on one address (default `0.0.0.0:8443`) with TLS 1.3, requires
  a client certificate chaining to the control plane CA with EKU `clientAuth` and
  CN `adguard-admin`. Nothing is served without one. There is no plaintext port.

## 2. The agent binary

Repo path `agent/`, Go 1.24, module `adguard-admin/agent`, binary
`adguard-admin-agent`. Dependencies: standard library plus `gopkg.in/yaml.v3`
(AdGuardHome.yaml edits). Shells out to `docker`, `systemctl`, `journalctl`, the
distro package manager and `dnsdist` (console client); never to a shell string
built from control-plane data (always `exec.Command(name, args...)`).

### Files

| Path | Content |
|---|---|
| `/etc/adguard-admin-agent/agent.json` | `{"listen","name","agent_id","control_plane_url","dnsdist_api_key","dnsdist_console_key","created_at"}` mode 0600 |
| `/etc/adguard-admin-agent/agent.key`, `agent.crt`, `ca.crt` | PEM, key 0600 |
| `/var/lib/adguard-admin-agent/desired/{adguard,dnsdist,keepalived}.json` | last accepted spec, so the agent re-converges after a reboot |
| `/var/lib/adguard-admin-agent/dnsdist/dnsdist.conf` | rendered Lua |
| `/var/lib/adguard-admin-agent/dnsdist/drained.json` | `["backend-name", ...]` |
| `/var/lib/adguard-admin-agent/status/*.json` | last status per role (optional cache) |

Flags `--config-dir` and `--state-dir` (env `AGENT_CONFIG_DIR`, `AGENT_STATE_DIR`)
override the two roots, which is how tests and the manual smoke test run it
unprivileged.

### Commands

```
adguard-admin-agent version
adguard-admin-agent enroll --url <control-plane base URL> --token <provisioning token>
                           [--listen 0.0.0.0:8443] [--address <ip-or-host>] [--name <name>]
adguard-admin-agent serve
adguard-admin-agent probe-dns <host:port>      # exit 0 if a DNS query is answered within 2s (keepalived track script)
```

`enroll`: generate an ECDSA P-256 key, build a CSR (CN = `--name` or hostname),
POST `{url}/api/provision/{token}/enroll` with

```json
{"csr_pem": "...", "hostname": "host-a", "address": "10.0.0.11", "port": 8443,
 "os": "linux", "arch": "amd64", "agent_version": "0.1.0"}
```

and write `agent.crt`, `ca.crt`, `agent.key`, `agent.json` from the reply
(section 4). `--address` defaults to the local source address used to reach the
control plane host (UDP connect trick). Exit non-zero on any failure; print the
server's error text. `enroll` never starts the service; the install script does.

`serve`: load files, start the mTLS server, start the converge loop: every role
with a desired spec on disk is converged at start, after every accepted `PUT`,
and every 30 s. One goroutine per role, serialized by a per-role mutex; a `PUT`
returns 202 immediately and the status reflects progress.

### HTTP API (served only over mTLS)

#### `GET /v1/info`
```json
{"agent_version":"0.1.0","agent_id":12,"name":"host-a","hostname":"host-a",
 "os":"linux","arch":"amd64","kernel":"6.1.0","uptime_s":12345,
 "docker":true,"systemd":true,"package_manager":"apt",
 "listen":"0.0.0.0:8443","cert_not_after":"2027-10-23T10:00:00Z",
 "roles":["adguard","dnsdist"],
 "desired_hashes":{"adguard":"<hex>","dnsdist":"<hex>","keepalived":null}}
```
`roles` lists roles that have a desired spec with `enabled: true`.

#### `GET /v1/health`
```json
{"time":"...","load":[0.12,0.08,0.05],
 "mem":{"total_bytes":0,"available_bytes":0},
 "disks":[{"path":"/","total_bytes":0,"free_bytes":0},{"path":"/var/lib/docker","total_bytes":0,"free_bytes":0}],
 "services":{"adguard":{"present":true,"running":true,"kind":"docker","detail":"Up 3 days","version":"v0.107.80"},
             "dnsdist":{"present":true,"running":true,"kind":"docker","detail":"","version":"2.0.8"},
             "keepalived":{"present":false,"running":false,"kind":"none","detail":"","version":null}}}
```
`kind` is `docker`, `systemd` or `none`. Disks: `/` plus the Docker data root when
Docker is present. Floats are allowed in *status* bodies (only specs are hashed).

#### AdGuard role: `PUT /v1/adguard`, `GET /v1/adguard`

Spec:
```json
{"enabled":true,"install_method":"docker","image":"adguard/adguardhome:latest",
 "web_bind":"127.0.0.1","web_port":3000,
 "dns_bind":["0.0.0.0"],"dns_port":53,
 "admin_username":"admin","admin_password":"..."}
```
Defaults: `install_method` `docker`; `image` as shown; `web_bind` `127.0.0.1`;
`web_port` 3000; `dns_bind` `["0.0.0.0"]`; `dns_port` 53.

Semantics:
- `docker`: container `adguardhome`, image as given, `--restart unless-stopped`,
  volumes `adguardhome-work:/opt/adguardhome/work` and
  `adguardhome-conf:/opt/adguardhome/conf`, `-p {web_bind}:{web_port}:3000/tcp`,
  and for every `dns_bind` entry `-p {bind}:{dns_port}:53/tcp` and `/udp`.
  Labels `adguard-admin.managed=true` and `adguard-admin.spec-hash=<hash>`. The
  container is recreated (volumes kept) when the label hash differs from the
  desired hash or the image reference changed. The previous container is kept,
  renamed, until the new one answers, then removed.
- `bare_metal`: install with AdGuard's official `install.sh` into
  `/opt/AdGuardHome` when absent. After the wizard, bind changes are applied by
  stopping the service, editing `AdGuardHome.yaml` (`dns.bind_hosts`, `dns.port`,
  `http.address`) and starting it.
- First-run wizard: wait for `GET http://127.0.0.1:{web_port}/control/install/get_addresses`
  (docker) or `:3000` (bare), then `POST /control/install/configure` with the web
  and dns settings and the admin credentials. If the instance is already
  configured, verify the credentials with `GET /control/status`; if they are
  rejected the role is `error` with message
  `credentials rejected; the instance was configured before this agent managed it`.
- `enabled:false` stops the container/service but removes nothing.

Status:
```json
{"state":"ready","desired_hash":"<hex>","applied_hash":"<hex>","version":"v0.107.80",
 "message":"","last_change":"...","web_url_local":"http://127.0.0.1:3000",
 "install_method":"docker","container":"adguardhome"}
```
`state` ∈ `absent`, `installing`, `configuring`, `ready`, `stopped`, `error`.

#### `ANY /v1/adguard/api/{path}`
Reverse proxy to `http://127.0.0.1:{web_port}/{path}` (query string preserved,
body streamed, `Authorization` passed through, hop-by-hop headers stripped). 503
with `{"error":"adguard is not ready"}` when the role is not `ready`.
The control plane's AdGuard client uses `https://{agent}/v1/adguard/api` as its
base URL, so `/control/status` becomes `/v1/adguard/api/control/status`.

#### `POST /v1/adguard/update`
Docker: pull the image; if the digest moved, recreate as above. Bare-metal:
`POST /control/update` locally with the stored credentials. Returns
`{"started":true,"message":"..."}` or `{"started":false,"message":"already current"}`.

#### dnsdist role: `PUT /v1/dnsdist`, `GET /v1/dnsdist`

Spec:
```json
{"enabled":true,"install_method":"docker","image":"powerdns/dnsdist-20:2.0.8",
 "listen":["0.0.0.0:53"],
 "policy":"leastOutstanding",
 "ecs":true,
 "cache":{"enabled":false,"max_entries":100000},
 "healthcheck":{"name":"a.root-servers.net.","interval_s":1,"max_failures":3,"rise":2,"mode":"auto"},
 "acl":["127.0.0.0/8","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","::1/128","fc00::/7","fe80::/10"],
 "backends":[{"name":"dns-a","address":"127.0.0.1","port":5335,"weight":1,"order":1},
             {"name":"dns-b","address":"10.0.0.12","port":5335,"weight":1,"order":1}]}
```
`policy` ∈ `leastOutstanding`, `roundrobin`, `wrandom`, `whashed`, `firstAvailable`.
`healthcheck.mode` ∈ `auto`, `lazy`. Backend `name` is `[A-Za-z0-9_.-]{1,64}`.

Rendered Lua (the agent owns this; the control plane never sends code):
```lua
-- generated by adguard-admin-agent; hash <hex>
setLocal("0.0.0.0:53")                      -- first listen; addLocal for the rest
setACL({"127.0.0.0/8", ...})
newServer({name="dns-a", address="127.0.0.1:5335", weight=1, order=1,
           useClientSubnet=true, checkName="a.root-servers.net.", checkInterval=1,
           maxCheckFailures=3, rise=2, healthCheckMode="auto"})
setServerPolicy(leastOutstanding)
-- cache, only when enabled:
-- pc = newPacketCache(100000, {maxTTL=86400, minTTL=0}); getPool(""):setCache(pc)
webserver("127.0.0.1:8083")
setWebserverConfig({apiKey="<agent.json dnsdist_api_key>", acl="127.0.0.1/32,::1/128"})
controlSocket("127.0.0.1:5199")
setKey("<agent.json dnsdist_console_key>")   -- 32 random bytes, base64 (makeKey() format)
```
IPv6 backend addresses are rendered as `[addr]:port`. Strings are rendered with
Lua escaping; names and addresses are validated before rendering.

Semantics:
- `docker`: container `dnsdist`, `--network host`, `--restart unless-stopped`,
  our rendered directory mounted read-only over the image's config location,
  started so that it can bind port 53 on the host network (the implementer
  verifies the official image's user and command and picks `--cap-add
  NET_BIND_SERVICE` and/or an explicit user accordingly; never set
  `DNSDIST_API_KEY`, which would open the API on the host network).
  Labels as for AdGuard. Apply = write config, validate with
  `dnsdist --check-config` (inside a throwaway container of the same image, or
  the host binary), then `docker restart` when only the config changed and
  recreate when the image changed. Re-apply drains after every restart.
- `bare_metal`: distro package `dnsdist` (apt/dnf/apk), config at
  `/etc/dnsdist/dnsdist.conf`, `systemctl restart dnsdist`.
- Console commands run through the dnsdist client (`dnsdist -c ... -e <lua>`),
  with the key from `agent.json`, never through a shell.
- Drain: `for _,s in ipairs(getServers()) do if s:getName()=="NAME" then s:setDown() end end`;
  undrain: same with `s:setAuto()`. Drained names persist across restarts.

Status (read from `http://127.0.0.1:8083/api/v1/servers/localhost` and
`/statistics` with header `X-API-Key`):
```json
{"state":"ready","desired_hash":"<hex>","applied_hash":"<hex>","version":"2.0.8",
 "message":"","last_change":"...","install_method":"docker",
 "backends":[{"name":"dns-a","address":"127.0.0.1:5335","state":"up","drained":false,
              "qps":3.2,"queries":120394,"responses":120390,"drop_rate":0.0,"send_errors":0,
              "latency_ms":1.4,"outstanding":0,"weight":1,"order":1,"pools":[""],
              "health_failures":0}],
 "frontends":[{"address":"0.0.0.0:53","protocol":"udp","queries":100,"responses":100},
              {"address":"0.0.0.0:53","protocol":"tcp","queries":1,"responses":1}],
 "stats":{"queries":0,"responses":0,"servfail-responses":0,"downstream-timeouts":0,
          "downstream-send-errors":0,"cache-hits":0,"cache-misses":0,"uptime":0,
          "latency-avg100":0,"latency-avg1000":0,"latency-avg10000":0,
          "real-memory-usage":0,"cpu-user-msec":0,"cpu-sys-msec":0,"noncompliant-queries":0},
 "drained":["dns-b"]}
```
`stats` is the full flat `name -> number` map from dnsdist's statistics
endpoint (the keys above are the ones the UI relies on). `state` ∈ `absent`,
`installing`, `ready`, `stopped`, `error`. Backend `state` is lowercased
`up`/`down`.

#### `POST /v1/dnsdist/backends/{name}/drain`, `POST /v1/dnsdist/backends/{name}/undrain`
`{"ok":true}`; 404 if the name is not in the applied spec.

#### keepalived role: `PUT /v1/keepalived`, `GET /v1/keepalived`

Spec:
```json
{"enabled":true,"vip":"10.0.0.53/24","interface":"","router_id":53,"priority":150,
 "auth_pass":"8charsMx","peers":["10.0.0.12","10.0.0.13"],"src_ip":"10.0.0.11",
 "check_dns":"127.0.0.1:53"}
```
`interface` empty = the interface that carries `src_ip`. `auth_pass` is 1 to 8
characters. `peers` are unicast peers (the other balancers in the zone).
`check_dns` empty disables the track script.

Rendered `/etc/keepalived/keepalived.conf`:
```
global_defs { enable_script_security script_user root }
vrrp_script chk_dns { script "/usr/local/bin/adguard-admin-agent probe-dns 127.0.0.1:53" interval 2 timeout 2 fall 2 rise 2 weight -60 }
vrrp_instance adguard_admin_53 {
  state BACKUP  interface eth0  virtual_router_id 53  priority 150  advert_int 1
  authentication { auth_type PASS  auth_pass 8charsMx }
  unicast_src_ip 10.0.0.11
  unicast_peer { 10.0.0.12  10.0.0.13 }
  virtual_ipaddress { 10.0.0.53/24 }
  track_script { chk_dns }
}
```
Installed as the distro package; `systemctl restart keepalived` on change.

Status:
```json
{"state":"ready","desired_hash":"<hex>","applied_hash":"<hex>","version":"2.2.8",
 "message":"","last_change":"...","vip_owner":true,"interface":"eth0"}
```
`vip_owner` is true when the VIP address is currently assigned to a local interface.

#### `POST /v1/services/{adguard|dnsdist|keepalived}/restart` → `{"ok":true,"message":""}`
#### `GET /v1/logs?service={adguard|dnsdist|keepalived|agent}&lines=200` → `{"lines":["..."]}` (max 2000)
#### `POST /v1/cert/renew` → `{"csr_pem":"..."}` (new key held in memory until `PUT /v1/cert`)
#### `PUT /v1/cert` body `{"cert_pem":"...","ca_pem":"..."}` → `{"ok":true,"not_after":"..."}`; 409 if no renewal is pending; the live TLS certificate is swapped without a restart.

## 3. Control plane: PKI

- `AgentCA` (one row): CA certificate and Fernet-encrypted key; the control
  plane's own client certificate (CN `adguard-admin`, EKU clientAuth) and
  encrypted key. Created on first start. CA validity 20 years, client cert 5
  years, agent certs 1 year, renewed by the control plane when under 120 days
  remain.
- Agent certs: EKU serverAuth only; SAN = the enrolled address (IP or DNS);
  CN = agent name. The control plane verifies agents against the CA and the
  SAN, and never against the per-server pinned `tls_cert` column.
- Material is written to `{DATA_DIR}/pki/` (`ca.crt`, `client.crt`,
  `client.key`, mode 0600) at startup for httpx.

## 4. Control plane: enrollment and downloads

`POST /api/provision/{token}/enroll` (unauthenticated, token-gated, single use)
Request: section 2 `enroll` body. Response 200:
```json
{"agent_id":12,"name":"host-a","cert_pem":"...","ca_pem":"...","not_after":"..."}
```
Effects: consumes the token (`completed`), creates `Agent`, and from the token's
`roles` creates a `Server` (role `adguard`, url `https://{address}:{port}/v1/adguard/api`,
generated admin credentials) and/or a `LoadBalancer` (role `dnsdist`). Errors:
404 unknown, 409 used, 410 revoked/expired, 400 invalid address or CSR.

`GET /api/agents/download/manifest` → `{"version":"0.1.0","files":{"linux/amd64":{"sha256":"...","size":0},"linux/arm64":{...},"linux/arm":{...}}}`
`GET /api/agents/download/linux/{amd64|arm64|arm}` → the binary. Both
unauthenticated (public artefacts, like the current `docker-agent.sh`). The
binaries live in `AGENT_BIN_DIR` (default `/app/agent-bin`), built by a Go stage
in the Dockerfile; 404 when absent (API-only dev runs).

`GET /api/provision/{token}/install.sh` renders:
```bash
#!/usr/bin/env bash
set -euo pipefail
BASE_URL='...'; TOKEN='...'; LISTEN='0.0.0.0:8443'; ADDRESS=''
# root + curl + systemd checks; arch from uname -m (x86_64->amd64, aarch64->arm64, armv7l->arm)
# fetch manifest, download binary to a temp file, verify sha256, install 0755 to /usr/local/bin
# adguard-admin-agent enroll --url "$BASE_URL" --token "$TOKEN" --listen "$LISTEN" [--address "$ADDRESS"]
# write /etc/systemd/system/adguard-admin-agent.service (serve; Restart=always; After=network-online.target docker.service)
# systemctl daemon-reload && systemctl enable --now adguard-admin-agent
```
No `eval`, no fetched config. The only interpolated values are the base URL, the
token, the listen address and the optional connect address, all shell-quoted and
validated.

## 5. Control plane: data model additions

```
AgentCA        id, ca_cert_pem, ca_key_enc, client_cert_pem, client_key_enc, created_at
Agent          id, name, url, zone_id, address, port, hostname, os, arch, version,
               cert_pem, cert_not_after, status (SyncStatus), last_seen, last_error,
               info (json), health (json), created_at
Server         + agent_id, dns_port (53), expose_web_ui (false), agent_state (json AdGuardStatus),
               lb_state (json: {"up": n, "down": n, "drained": n, "qps": x, "balancers": [{"id","name","state","qps","drained"}]})
Zone           + vip (CIDR or null), vrrp_router_id (int, default = 50 + zone id), vrrp_auth_enc
LoadBalancer   id, name, zone_id, agent_id, enabled, install_method, image,
               listen_addresses (json), policy, ecs, cache_enabled, cache_max_entries,
               hc_name, hc_interval_s, hc_max_failures, hc_rise, hc_mode, acl (json),
               vrrp_priority (100), vip_interface (""),
               desired_hash, applied_hash, in_sync, status, last_synced, last_error,
               state (json DnsdistStatus), keepalived_state (json), created_at
LoadBalancerBackend  id, load_balancer_id, server_id, enabled (true), weight (1), order (1)
ProvisioningToken    + roles (json, default ["adguard"]), agent_port (8443), vrrp_priority (100),
                       expose_web_ui (false)
SyncStatus     + provisioning
```

Derived rules:
- Backends of a balancer = enabled AdGuard servers in its zone, each at
  `(server.dns_address, server.dns_port)`, where `dns_address` is `127.0.0.1`
  when the server shares the balancer's agent, else the server's agent address
  (or the host of `Server.url` for servers without an agent). Overrides from
  `LoadBalancerBackend` apply by `server_id`.
- An AdGuard server whose agent also runs a dnsdist balancer gets
  `dns_bind ["127.0.0.1"]` and `dns_port 5335` (the balancer owns :53); otherwise
  `dns_bind ["0.0.0.0"]` and its own `dns_port`.
- `web_bind` is `0.0.0.0` when `expose_web_ui` else `127.0.0.1`.
- keepalived spec exists only when the zone has a `vip`; `peers` = addresses of
  the zone's other enabled balancers' agents; `src_ip` = this agent's address.

## 6. Control plane: HTTP API for the UI

Auth as everywhere: viewer reads, editor writes, admin deletes agents.

```
GET    /api/agents                      -> [AgentRead]
GET    /api/agents/{id}                 -> AgentRead
POST   /api/agents/{id}/refresh         -> AgentRead            (info + health now)
GET    /api/agents/{id}/logs?service=&lines=   -> {"lines": [...]}
POST   /api/agents/{id}/services/{name}/restart -> {"ok": true, "message": ""}
POST   /api/agents/{id}/renew-cert      -> AgentRead
DELETE /api/agents/{id}                 (admin; 409 while a server or balancer references it unless ?force=true, which detaches them)
GET    /api/agents/download/manifest    (public)
GET    /api/agents/download/linux/{arch} (public)

AgentRead = {id, name, url, zone_id, address, port, hostname, os, arch, version, status,
             last_seen, last_error, cert_not_after, roles: [...], health: {...}|null,
             info: {...}|null, server_ids: [...], load_balancer_ids: [...], created_at}

GET    /api/load-balancers              -> [LoadBalancerRead]
POST   /api/load-balancers              <- LoadBalancerCreate
GET    /api/load-balancers/{id}         -> LoadBalancerRead
PATCH  /api/load-balancers/{id}         <- LoadBalancerUpdate
DELETE /api/load-balancers/{id}
GET    /api/load-balancers/{id}/state   -> {"dnsdist": DnsdistStatus|null, "keepalived": KeepalivedStatus|null}  (fresh from the agent)
POST   /api/load-balancers/{id}/sync    -> LoadBalancerRead   (reconcile now)
POST   /api/load-balancers/{id}/restart -> {"ok": true}
PUT    /api/load-balancers/{id}/backends/{server_id}  <- {enabled, weight, order} -> LoadBalancerRead
POST   /api/load-balancers/{id}/backends/{server_id}/drain    -> {"ok": true}
POST   /api/load-balancers/{id}/backends/{server_id}/undrain  -> {"ok": true}

LoadBalancerRead = {id, name, zone_id, agent_id, enabled, install_method, image,
   listen_addresses, policy, ecs, cache_enabled, cache_max_entries,
   hc_name, hc_interval_s, hc_max_failures, hc_rise, hc_mode, acl,
   vrrp_priority, vip_interface, vip (from zone), status, in_sync, last_synced, last_error,
   desired_hash, applied_hash, state: DnsdistStatus|null, keepalived_state: KeepalivedStatus|null,
   backends: [{server_id, server_name, address, port, enabled, weight, order,
               live: {state, drained, qps, queries, latency_ms, outstanding, drop_rate}|null}],
   created_at}
LoadBalancerCreate = {name, zone_id, agent_id, enabled?, install_method?, image?, listen_addresses?,
   policy?, ecs?, cache_enabled?, cache_max_entries?, hc_*?, acl?, vrrp_priority?, vip_interface?}
LoadBalancerUpdate = every field optional.

ZoneRead/Create/Update  + vip, vrrp_router_id   (plus ZoneRead.load_balancer_count)
ServerRead              + agent_id, dns_port, expose_web_ui, agent_state, lb_state
ServerCreate/Update     + dns_port, expose_web_ui (agent_id is set by enrollment, read-only)

ProvisionRequest = {name, zone_id?, roles: ["adguard"|"dnsdist", ...] (default ["adguard"]),
   method ("docker"|"bare_metal", AdGuard install), connect_address?, agent_port? (8443),
   prune?, auto_update?, expose_web_ui?, vrrp_priority?}
ProvisionTokenRead = {id, name, zone_id, roles, method, auto_update, connect_address, agent_port,
   vrrp_priority, expose_web_ui, status, token, command, created_at, expires_at, completed_at,
   server_id, agent_id, load_balancer_id}
```

`GET /api/stats` additionally returns `agents`, `agents_online`, `load_balancers`,
`load_balancers_in_sync`.

## 7. UI

- **Hosts** (`/hosts`): one row per agent: name, zone, address, roles as badges,
  agent version, status, load / memory / disk, certificate expiry. Row menu:
  refresh, view logs (service picker), restart service, renew certificate,
  delete (admin). Empty state explains that hosts appear through Provisioning.
- **Load balancers** (`/load-balancers`): table (name, zone, VIP with owner
  badge, status, backends up/down, QPS, sync) and a detail panel with the
  backends table (state, drained, QPS, queries, share bar as a percentage of the
  balancer's total queries, latency, outstanding, drop rate, weight, order),
  frontends, cache hit rate when enabled, the stats keys listed in section 2,
  and actions: drain/undrain, set weight/order/enabled, restart dnsdist, sync
  now, logs. Create/edit modal with every spec field, grouped: basics (name,
  zone, host), listeners and policy, health check, cache, ACL, VRRP priority
  and interface. Zone VIP is edited on the Zones page and shown here read-only.
- **Zones**: add VIP (CIDR) and router id fields with a hint that a VIP needs at
  least one balancer in the zone.
- **Servers**: a Host column (agent name, or "direct" for servers added by URL),
  the AdGuard role state when not `ready` (installing, configuring, error with
  message), and the balancer view (`lb_state`: up/down/drained and QPS). The edit
  modal gains `dns_port` and `expose_web_ui` for agent-managed servers; URL,
  username and password are read-only for them.
- **Provisioning**: role checkboxes (AdGuard Home, dnsdist balancer), the AdGuard
  install method, optional connect address, agent port, prune, auto-update,
  expose web UI, VRRP priority (when dnsdist is ticked and the zone has a VIP).
  The one-liner result view says it installs the agent and that the roles are
  converged by the control plane afterwards.
- **Dashboard**: a tile per zone with a VIP: VIP, owner host, QPS, backends up /
  total; and the agent counts from `/api/stats`.
- **Updates**: agent-managed Docker servers are upgradeable from here (the
  "on-box updater" wording goes away for them).
- Navigation order: Dashboard, Zones, Hosts, Servers, Load Balancers, DNS
  Records, DNS Settings, Filtering, Query Log, Updates; Provisioning (editor);
  Users (admin).

## 8. Addendum: IPVS direct-routing mode

A second balancer mode. `LoadBalancer.mode` is `dnsdist` (default, everything
above) or `ipvs`. All balancers in a zone share one mode, and `ipvs` requires
the zone to have a VIP. In `ipvs` mode the balancer host runs **no dnsdist**:
keepalived owns the VIP *and* programs the kernel's IPVS table in
direct-routing mode, so backends see the real client address and reply
straight to the client. Every backend (including the director hosts
themselves) carries the VIP on loopback with ARP suppressed, and AdGuard
listens on `0.0.0.0:53` on all of them.

### 8.1 keepalived spec, `ipvs` block (agent `PUT /v1/keepalived`)

```json
{"enabled":true,"vip":"10.0.0.53/24","interface":"","router_id":53,"priority":150,
 "auth_pass":"8charsMx","peers":["10.0.0.12"],"src_ip":"10.0.0.11","check_dns":"",
 "ipvs":{"enabled":true,"vip":"10.0.0.53","ports":[53],"protocols":["udp","tcp"],
         "algo":"wlc",
         "backends":[{"name":"dns-a-1","address":"10.0.0.11","port":53,"weight":1},
                     {"name":"dns-b-2","address":"10.0.0.12","port":53,"weight":1}],
         "check":{"interval_s":2,"timeout_s":2,"retry":2}}}
```
`ipvs` absent or `enabled:false` = pure VRRP as before. `algo` ∈ `rr`, `wrr`,
`lc`, `wlc`, `sh`. `check_dns` is empty in ipvs mode (the VRRP track script
would probe the local AdGuard, which is a backend, not the director's job);
the director's own backend entry is health-checked like any other.

Rendered after the `vrrp_instance`, one block per port and protocol:
```
virtual_server 10.0.0.53 53 {
  delay_loop 2
  lb_algo wlc
  lb_kind DR
  protocol UDP
  real_server 10.0.0.11 53 {
    weight 1
    inhibit_on_failure
    MISC_CHECK { misc_path "/usr/local/bin/adguard-admin-agent probe-dns 10.0.0.11:53" misc_timeout 2 }
    retry 2
    delay_before_retry 1
  }
}
```
`inhibit_on_failure` keeps a failed backend in the table at weight 0, so the
status below can report it as `down` instead of it vanishing. The agent installs
`ipvsadm` alongside `keepalived` and makes sure the `ip_vs` module loads
(`/etc/modules-load.d/adguard-admin-ipvs.conf`).

### 8.2 keepalived status, `ipvs` block (agent `GET /v1/keepalived`)

```json
{"state":"ready", "...":"as before",
 "ipvs":{"present":true,"services":2,
         "backends":[{"name":"dns-a-1","address":"10.0.0.11","port":53,"weight":1,
                      "state":"up","drained":false,
                      "active_conns":0,"inactive_conns":12,"conns":1234,
                      "in_pkts":1234,"in_bytes":98765,"cps":0.5,"in_pps":0.5}]}}
```
Read with `ipvsadm -Ln --stats` and `ipvsadm -Ln --rate` (parsed, never
shelled); UDP and TCP services for the same backend are summed. `state` is
`up` when the backend's IPVS weight is above zero on every service, `down`
otherwise. Out-direction counters are omitted on purpose: in direct routing the
replies never pass the director. `present:false` when no virtual server is
programmed.

### 8.3 drains in ipvs mode

`POST /v1/keepalived/backends/{name}/drain` → `ipvsadm -e` sets that backend's
weight to 0 on every service; `undrain` restores the spec weight. Persisted in
`keepalived/drained.json` and re-applied after a keepalived restart. A
keepalived check transition on that backend can restore its weight; the agent
re-applies drains every converge tick (30 s).

### 8.4 new role: `ipvs_backend` (agent `PUT /v1/ipvs-backend`, `GET /v1/ipvs-backend`)

Spec: `{"enabled":true,"vip":"10.0.0.53"}`. Converges on every backend host in
an ipvs zone, directors included:
- `ip addr add 10.0.0.53/32 dev lo` (idempotent; removed on `enabled:false`);
- `/etc/sysctl.d/90-adguard-admin-ipvs.conf` with
  `net.ipv4.conf.all.arp_ignore=1`, `net.ipv4.conf.all.arp_announce=2`,
  `net.ipv4.conf.lo.arp_ignore=1`, `net.ipv4.conf.lo.arp_announce=2`, applied
  immediately with `sysctl -w`; file removed and values reset on `enabled:false`.

Status: `{"state":"ready"|"error"|"stopped","desired_hash","applied_hash",
"message","last_change","vip_present":true,"sysctls_ok":true}`.
`desired_hashes` in `/v1/info` gains `ipvs_backend`.

### 8.5 control plane derivations

- `LoadBalancer.mode` (`dnsdist`|`ipvs`), `LoadBalancer.ipvs_algo` (default
  `wlc`). `ProvisionRequest.lb_mode`, `ProvisioningToken.lb_mode`.
- Zone mode = the mode of its balancers; a create/update that would mix modes
  in a zone is refused (409); `ipvs` without a zone VIP is refused (400).
- In an ipvs zone, every AdGuard server gets `dns_bind ["0.0.0.0"]`,
  `dns_port 53` (never the loopback 5335 of co-located dnsdist), and every
  agent-managed server in the zone gets the `ipvs_backend` spec. Servers added
  by URL in an ipvs zone must be prepared by hand (documented).
- IPVS backends are addressed by the server's host address (the agent address,
  or the URL host for direct servers), never 127.0.0.1; port 53.
- When a zone leaves ipvs mode, `ipvs_backend` is pushed with `enabled:false`
  to every agent that reports a desired hash for it; when a zone leaves dnsdist
  mode, `dnsdist` is pushed disabled the same way.
- `LoadBalancerRead` gains `mode`, `ipvs_algo`; `backends[].live` is filled from
  `keepalived_state.ipvs.backends` in ipvs mode (`qps` ← `in_pps`,
  `queries` ← `in_pkts`, plus `active_conns`, `inactive_conns`, `conns`).
  `state` (the dnsdist snapshot) is null in ipvs mode.
- Drain/undrain API routes to the keepalived drain endpoints in ipvs mode.

### 8.6 UI

- Mode selector on the balancer create/edit modal and on the Provisioning
  form (shown when dnsdist is ticked). In ipvs mode the dnsdist-only fields
  (listen addresses, policy, ECS, cache, ACL, image, install method,
  health-check name and mode) are hidden; `ipvs_algo` and the check
  interval/retry are shown; a note says the zone needs a VIP and that AdGuard
  listens on :53 on every backend.
- Detail panel in ipvs mode: backends table with state, drained, conns, active
  and inactive connections, packets in, packets/s in, share bar by packets in;
  no latency/outstanding/drop columns; the dnsdist statistics card is replaced
  by an "IPVS" card (services programmed, VIP owner); frontends card hidden.
- Table: mode badge next to the name.

## 9. Addendum: agent self-update, AdGuard reinstall, probe robustness

### 9.1 Probe robustness (agent)

The AdGuard role's HTTP client must **not follow redirects** (`CheckRedirect`
returning `http.ErrUseLastResponse`): any HTTP response, including a 302 to a
login or install page, means the server answered. The wait loop's timeout
message carries the last transport error. The first-run check and the
credential check already use endpoints that do not redirect.

### 9.2 Agent self-update

`POST /v1/self-update` (mTLS, from the control plane only):
```json
{"version":"0.2.0","url":"https://admin.example.com/api/agents/download/linux/amd64","sha256":"<hex>"}
```
The agent downloads `url` with a plain HTTPS/HTTP client (the same trust as
enrollment: it is the control plane's own URL; integrity comes from the
SHA-256 delivered over mTLS), limit 64 MiB, timeout 120 s; verifies the hash;
writes the file next to the running executable (`os.Executable()`) as
`<name>.new` with mode 0755; renames it over the current path; replies
`{"ok":true,"version":"0.2.0","restarting":true}` and exits with status 0 one
second later so systemd (`Restart=always`) starts the new binary. When not
running under systemd (`INVOCATION_ID` unset) it still replaces the binary and
replies `restarting:false` with a message to restart by hand. A hash mismatch
or a version equal to the running one is a 409 with `{"error": ...}` and
nothing is written. `GET /v1/info` already reports `agent_version`.

Control plane: `Agent.update_attempted_at`, `Agent.update_error`. During
`reconcile_agent`, when `AGENT_AUTO_UPDATE` (default true) is on, the download
manifest has a version, the agent reports a different one, and the last
attempt is older than `AGENT_UPDATE_RETRY_MINUTES` (default 30), the control
plane posts a self-update and skips the rest of that pass (the agent is about
to restart). `POST /api/agents/{id}/update` does the same on demand (editor).
`AgentRead` gains `update_available: bool` (manifest version known and
different), `update_attempted_at`, `update_error`. The Hosts page shows an
"update available" badge next to the agent version and an **Update agent**
action; the manifest version is shown in the page header.

### 9.3 AdGuard reinstall (wipe)

`POST /v1/adguard/reset` (mTLS): docker: stop and remove `adguardhome` and
`adguardhome-prev`, remove the `adguardhome-work` and `adguardhome-conf`
volumes; bare-metal: stop the service and delete `AdGuardHome.yaml` and the
`data/` directory under the install dir. Then clear the role's applied hash
and converge immediately, so the first-run wizard runs again with the
control plane's credentials. Replies `{"ok":true}`; 409 while a converge is
in flight.

Control plane: `POST /api/servers/{id}/reinstall` (**admin**, audit-logged),
409 for a server without an agent. UI: Servers row menu, admin only,
"Reinstall AdGuard (wipe)" with a confirm that says the instance's own
settings, query log and statistics on that host are deleted and the control
plane's records and settings are re-applied.

### 8.7 IPVS diagnostics (agent and UI)

"No virtual server programmed" has several causes the agent can tell apart.
The keepalived status `ipvs` block gains:

```json
"ipvs":{"present":false,"services":0,"backends":[],
        "message":"ipvsadm -Ln: Can't initialize ipvs: Protocol not available",
        "diagnostics":{"ipvsadm":true,"module_loaded":false,"proc_ip_vs":false,
                       "config_has_virtual_servers":true,"keepalived_running":true,
                       "modprobe_error":"modprobe: FATAL: Module ip_vs not found in directory /lib/modules/...",
                       "checked_at":"2026-10-23T03:10:00Z"}}
```

- `ipvsadm`: the binary is on PATH. `module_loaded`: `/proc/net/ip_vs` exists
  (the module is loaded or built in). `config_has_virtual_servers`: the config
  the agent rendered contains at least one `virtual_server` block.
  `keepalived_running`: the unit is active. `modprobe_error`: the last
  `modprobe ip_vs` failure, empty when it succeeded.
- When `ipvsadm` is missing but `/proc/net/ip_vs` exists, the agent reads the
  kernel table from `/proc/net/ip_vs` (services, destinations, weight,
  ActiveConn, InActConn) so `present`, `services`, `backends[].state`,
  `weight`, `active_conns` and `inactive_conns` are still reported; packet
  counters are then null.
- The agent runs `modprobe ip_vs` on every keepalived converge in ipvs mode
  (not only once) and records the error.

UI (Load balancers detail, ipvs mode): the IPVS card shows the diagnostics as
a checklist (green/red) and, when `present` is false, the `message` plus one
hint chosen from the diagnostics: module not loaded → "the ip_vs kernel module
is not loaded (modprobe error: …); check that the kernel ships it";
ipvsadm missing → "ipvsadm is not installed; the agent installs it with
keepalived, see the agent log"; no virtual_server in config → "the rendered
keepalived config has no virtual_server block: the zone VIP or mode changed
and the host has not converged yet"; keepalived not running → "keepalived is
not running on this host; see its log"; otherwise "keepalived is running and
the module is loaded but no service is programmed; check the keepalived log
for the virtual_server section". Backend rows show `weight` and the
connection counters even when packet counters are null.
