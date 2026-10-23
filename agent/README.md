# adguard-admin-agent

The on-host agent for AdGuard Admin. One static Go binary that fronts AdGuard
Home, dnsdist and keepalived on a managed host over mutual TLS. The interface
it implements is [docs/design/agent-api.md](../docs/design/agent-api.md).

## Build

Go 1.24. Only dependency: `gopkg.in/yaml.v3` (AdGuardHome.yaml edits).

```sh
cd agent
go test ./... && go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags="-s -w -X adguard-admin/agent/internal/server.Version=$VERSION" \
  -o adguard-admin-agent-linux-amd64 ./cmd/adguard-admin-agent
# arm64: GOARCH=arm64 ; 32-bit Pi: GOARCH=arm GOARM=7 -> adguard-admin-agent-linux-arm
```

The control plane serves these three files as
`/api/agents/download/linux/{amd64,arm64,arm}` (the names match `uname -m`
mapped by the install script: x86_64→amd64, aarch64→arm64, armv7l→arm).

## Run

```
adguard-admin-agent enroll --url https://admin.example --token <token> [--listen 0.0.0.0:8443] [--address 10.0.0.11] [--name host-a]
adguard-admin-agent serve
adguard-admin-agent probe-dns 127.0.0.1:53      # keepalived track script / IPVS MISC_CHECK; exit 0 on any DNS answer
adguard-admin-agent version
```

`--config-dir` (env `AGENT_CONFIG_DIR`, default `/etc/adguard-admin-agent`)
and `--state-dir` (`AGENT_STATE_DIR`, default `/var/lib/adguard-admin-agent`)
apply to `enroll` and `serve`. With both pointed at writable directories the
agent runs unprivileged for tests; roles then report `kind: none` for Docker
and systemd and `/v1/info` and `/v1/health` still answer.

Files: `agent.json` (listen, name, agent id, control plane URL, dnsdist API and
console keys; 0600), `agent.key`, `agent.crt`, `ca.crt` in the config dir;
`desired/<role>.json`, `status/<role>.json`, `dnsdist/{dnsdist.conf,applied.json,drained.json}`,
`keepalived/drained.json` in the state dir.

## Roles and endpoints

| Role | Endpoints | What it converges |
|---|---|---|
| `adguard` | `PUT/GET /v1/adguard`, `ANY /v1/adguard/api/*`, `POST /v1/adguard/update` | AdGuard Home container or native install |
| `dnsdist` | `PUT/GET /v1/dnsdist`, `POST /v1/dnsdist/backends/{name}/(un)drain` | dnsdist balancer (L7 proxy mode) |
| `keepalived` | `PUT/GET /v1/keepalived`, `POST /v1/keepalived/backends/{name}/(un)drain` | VRRP VIP; with an `ipvs` block also the kernel IPVS direct-routing balancer |
| `ipvs_backend` | `PUT/GET /v1/ipvs-backend` | the zone VIP on `lo` plus the ARP sysctls that make a host an IPVS real server |

Plus `GET /v1/info`, `GET /v1/health`, `POST /v1/services/{name}/restart`,
`GET /v1/logs`, `POST /v1/cert/renew`, `PUT /v1/cert`.

## Layout

| Package | Role |
|---|---|
| `internal/canon` | canonical JSON + SHA-256 spec hash, byte-identical to the control plane's Python definition |
| `internal/execx` | the only way programs are run: `exec.Command(name, args...)`, with a recording fake for tests |
| `internal/pki` | key/CSR/cert handling, live certificate holder, mTLS policy (CA chain + `clientAuth` EKU + CN `adguard-admin`) |
| `internal/roles` | desired-state manager: persist, converge loop (on PUT and every 30 s), status |
| `internal/roles/adguard` | AdGuard Home in Docker or native; first-run wizard; proxy target; update |
| `internal/roles/dnsdist` | Lua rendering, `--check-config`, container/package lifecycle, stats, drains |
| `internal/roles/keepalived` | keepalived.conf rendering (VRRP, and IPVS `virtual_server` blocks), package install, VIP ownership, ipvsadm stats and drains |
| `internal/roles/ipvsbackend` | loopback VIP and ARP sysctls for IPVS direct-routing real servers |
| `internal/server` | the HTTP API |
| `internal/enroll` | CSR enrollment against the provisioning token |
| `internal/aghyaml` | `dns.bind_hosts`, `dns.port`, `http.address` edits preserving the rest of the file |

## Verified facts the dnsdist role is built on

Read from `PowerDNS/pdns` master (`Dockerfile-dnsdist`, `dockerdata/startup.py`)
and the dnsdist manual page on 2026-10-23:

- The official image (`powerdns/dnsdist-20`) is Debian based, runs as user
  `pdns` (uid 953), entrypoint `tini -- /usr/local/bin/dnsdist-startup`, which
  execs `dnsdist --supervised --disable-syslog <argv>`. It has no `CMD`; any
  arguments given to `docker run` are passed to dnsdist.
- `startup.py` does not drop privileges and never sets `--uid/--gid`. If
  `DNSDIST_API_KEY` is set it writes `/etc/dnsdist/conf.d/_api.conf` with
  `webserver("0.0.0.0:8083")`, an ACL of `0.0.0.0/0` and a console on
  `0.0.0.0:5199`, so the agent never sets that variable.
- Because `pdns` cannot bind :53 on the host network, the agent starts the
  container as `--user 0:0` with `--cap-drop ALL --cap-add NET_BIND_SERVICE
  --cap-add SETUID --cap-add SETGID` and passes `--uid pdns --gid pdns` so
  dnsdist drops to `pdns` after binding (manual: `-u/--uid`, `-g/--gid` change
  the process user/group after sockets are bound).
- The rendered config directory is mounted read-only at `/etc/dnsdist/agent`
  (a directory, not a file, so an atomic rename of `dnsdist.conf` is seen by the
  container) and selected with `-C /etc/dnsdist/agent/dnsdist.conf`.
- `--check-config` validates a `-C` file and exits non-zero on errors; the agent
  runs it in a throwaway container of the same image (or the host binary).
- Console client: `-c/--client [address]` takes an *optional* argument, so the
  agent uses `--client=127.0.0.1:5199`; the key is `-k/--setkey <key>` (must
  match `setKey()`); `-e/--execute <cmd>` runs one command. In Docker this is
  `docker exec dnsdist dnsdist --client=... -k ... -e ...`.
- `getServer()` takes an index or UUID, not a name, so drains iterate
  `getServers()` and match `getName()`; `setDown()` disables health checks and
  stops traffic, `setAuto()` returns the backend to health-checked operation.
- dnsdist REST API: `GET /api/v1/servers/localhost` (servers with `name`,
  `address`, `state`, `qps`, `queries`, `responses`, `dropRate`, `sendErrors`,
  `latency`, `outstanding`, `weight`, `order`, `pools`, `healthCheckFailures`;
  plus `frontends` and `version`) and `/api/v1/servers/localhost/statistics`
  (`[{name,type,value}]`), key in header `X-API-Key`. There is no `drops`
  field; the contract's `drop_rate` maps `dropRate`.

## IPVS diagnostics

The keepalived status `ipvs` block always carries a `diagnostics` object so
"no virtual server programmed" can be told apart from its causes:

| Field | Meaning |
|---|---|
| `ipvsadm` | the binary is on PATH |
| `module_loaded` | `/proc/net/ip_vs` exists (module loaded or built in) |
| `proc_ip_vs` | that file is readable |
| `config_has_virtual_servers` | the config the agent last rendered (or the one on disk) contains a `virtual_server` block |
| `keepalived_running` | the unit is active |
| `modprobe_error` | the last `modprobe ip_vs` failure; the agent runs modprobe on every converge in ipvs mode and never fails the converge on it |
| `container` | `lxc`, `docker`, `podman`, `systemd-nspawn` or `""`, from `container=` in PID 1's environment, else `/.dockerenv` |
| `checked_at` | when the checks ran |

`message` is ipvsadm's last stderr line when it fails (for example
`ipvsadm -Ln: Are you sure that IP Virtual Server is built in the kernel or as module?`),
`ipvsadm is not installed`, or empty.

When ipvsadm is missing or fails but `/proc/net/ip_vs` exists, the agent reads
the kernel table itself (hex addresses and ports, IPv6 in brackets): `present`,
`services`, each backend's `state`, `weight`, `active_conns` and
`inactive_conns` are still reported; `conns`, `in_pkts`, `in_bytes`, `cps` and
`in_pps` are then JSON `null`, never zero, so a reader can tell "unknown" from
"idle".

**Containers (Proxmox LXC and the like).** `modprobe` cannot load modules
inside a container; `ip_vs` has to be loaded on the container's host node
(`modprobe ip_vs` there, persisted in `/etc/modules-load.d/`). When modprobe
fails and `container` is set, the agent log says so explicitly. keepalived
inside the container can then program IPVS once the host kernel has the module.

## Verified facts the IPVS mode is built on

From keepalived.conf(5) (Debian bookworm, keepalived 2.2.x), read 2026-10-23:

- `virtual_server <IPADDR> [<PORT>]`; the port may only be omitted for a
  persistent service. `persistence_timeout` is optional (default 6 minutes
  when set); the agent does not set it.
- The documented scheduler and method keywords are `lvs_sched
  rr|wrr|lc|wlc|lblc|sh|mh|dh|fo|ovf|lblcr|sed|nq|twos` and `lvs_method`
  (default NAT); `lb_algo` / `lb_kind` are the older aliases. The agent renders
  `lvs_sched` and `lvs_method DR`.
- `delay_loop` is the checker polling interval (default 60 s) at
  `virtual_server` level. `real_server` takes `weight` (default 1) and
  `inhibit_on_failure` ("set weight to 0 when healthchecker detects failure"),
  which is what lets a failed backend stay visible in `ipvsadm -Ln` at weight 0.
- `MISC_CHECK { misc_path "<program> [args]" misc_timeout <s> }`; arguments
  are allowed inside the quoted path. `retry` (MISC_CHECK default 0) and
  `delay_before_retry` (default 1 s for MISC_CHECK) are checker keywords, so
  the agent writes them inside the `MISC_CHECK` block.
- `enable_script_security` refuses root-run scripts whose path is writable by
  a non-root user; `/usr/local/bin/adguard-admin-agent` is installed root
  0755, and `script_user root` is kept from the VRRP configuration.
- `ipvsadm -Ln --stats --exact` / `--rate --exact` print full numbers (without
  `--exact` ipvsadm abbreviates with K/M/G; the parser accepts both). Plain
  `ipvsadm -Ln` carries `Forward Weight ActiveConn InActConn` per real server.
  Weights are edited live with `ipvsadm -e -u|-t VIP:PORT -r RS:PORT -g -w N`.

## Deviations from the contract

- **`retry` / `delay_before_retry` sit inside `MISC_CHECK`**, not at
  `real_server` level as section 8.1 sketches: keepalived documents them as
  checker keywords.
- **`lvs_sched` / `lvs_method` instead of `lb_algo` / `lb_kind`**: same
  semantics, the documented spelling for 2.x.
- **`VIPOwner` ignores loopback**: in ipvs mode every backend holds the VIP on
  `lo`, so only a non-loopback interface counts as owning it.
- **`modprobe ip_vs` failures are ignored** (containers, built-in module);
  keepalived loads the module itself when it programs a service.

- **`drop_rate` instead of `drops`** on backends (dnsdist exposes a rate, not a
  counter); `send_errors` is also included.
- **Backend hostnames are resolved by the agent** at render time (IPv4
  preferred) because `newServer()` accepts IP literals only. An unresolvable
  name fails the converge with a clear message.
- **The dnsdist applied hash lives in `dnsdist/applied.json`**, not a container
  label: labels cannot change on a running container, and a config-only change
  is applied with `docker restart`, keeping the container.
- **`GET /v1/dnsdist` fetches live data only while the role is `ready`**;
  otherwise the body carries the common fields with empty lists.
- **AdGuard `web_bind` must be an IP literal** (the contract's examples are);
  hostnames are rejected at `PUT`.
- **Bare-metal AdGuard wizard binds `dns_bind[0]`**, then the YAML edit applies
  the full `dns_bind` list (the wizard API takes a single address).
- **`POST /v1/services/agent/restart` is refused** (404): an agent that
  restarts itself mid-request cannot answer.


## Self-update and reinstall (contract section 9)

| Endpoint | What it does |
|---|---|
| `POST /v1/self-update` `{"version","url","sha256"}` | Downloads the binary (64 MiB cap, 120 s), verifies the SHA-256, writes `<exe>.new` (0755) beside `os.Executable()` and renames it over the running binary. Replies `{"ok":true,"version":...,"restarting":true}` and exits 0 one second later when `INVOCATION_ID` is set (systemd `Restart=always` starts the new binary). Without systemd it replies `restarting:false` and asks for a manual restart. 409 on a checksum mismatch or when the version equals the running one; nothing is written on any failure. |
| `POST /v1/adguard/reset` | Wipes the AdGuard install: docker removes `adguardhome`, `adguardhome-prev` and the `adguardhome-work` / `adguardhome-conf` volumes; bare-metal stops the unit and deletes `AdGuardHome.yaml` and `data/` under the install dir. Then clears the role's applied hash and wakes the converge loop, so the first-run wizard runs again with the control plane's credentials. 409 while a converge is in flight (the role's converge lock is tried, never waited on). |

Probe robustness: the AdGuard role's HTTP client never follows redirects
(`CheckRedirect` → `http.ErrUseLastResponse`). An unconfigured instance answers
`/control/status` with a 302 to its install page; following it could land on
an address the agent cannot reach and made a healthy container look silent.
The wait-loop timeout now carries the last transport error.

Command errors: `execx.Real` reports only the last meaningful stderr line
(skipping docker's "Run '... --help'" hint); set `AGENT_DEBUG=1` on the service
to log the full stderr of every failed command.
