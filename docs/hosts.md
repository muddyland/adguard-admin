# Hosts

A **host** is a machine that runs the **AdGuard Admin agent**. The agent is a
small static binary installed by [provisioning](provisioning.md); it is the only
thing the control plane talks to on a managed box, and it is reachable **only
over mutual TLS**.


## What the agent does

- **Converges roles.** The control plane sends each role a *desired state*
  (JSON, never code) and the agent installs, configures and restarts what is
  needed: the AdGuard Home container or native install, the dnsdist container or
  package, keepalived for the zone's virtual IP (and, in IPVS mode, its virtual
  servers), and the loopback VIP plus ARP settings that make a host a
  direct-routing backend. The agent re-applies the last desired state after a
  reboot without waiting for the control plane.
- **Runs AdGuard on the host network.** The AdGuard container uses
  `--network host`; the agent sets its listen addresses in `AdGuardHome.yaml`
  (loopback for the UI unless *expose web UI* is on; the DNS bind the zone's
  balancing mode needs). No published ports, so no Docker NAT in front of DNS,
  which IPVS direct routing requires. See [Load balancing](load-balancing.md#requirements-and-ports).
- **Fronts AdGuard's API.** AdGuard's admin interface stays on loopback; the
  control plane reaches it through the agent, so no AdGuard credential ever
  crosses the LAN in clear text and nothing on the network can lock the control
  plane out with bad logins. The embedded UI on the Servers page works through
  the same path. Tick **expose web UI** on a server if you want AdGuard's own
  UI reachable on the host's LAN address as well.
- **Reports health.** Load, memory, free disk under `/` and the Docker data root,
  and the state of each service. Shown on the Hosts page, so a box that is about
  to fall over is visible before it does.
- **Upgrades containers.** For an AdGuard container the agent pulls the image
  and recreates the container with the same volumes; see [Updates](updates.md).
- **Keeps logs reachable.** The Hosts page can tail the agent, AdGuard, dnsdist
  and keepalived logs, and restart any of the three services.

## Security model

- Every deployment has its own **CA**, generated on first start and stored in
  the database with its key encrypted by `FERNET_KEY`. Agent certificates are
  issued against a CSR the agent generated on the box: the control plane never
  sees a private key.
- Agent certificates carry **serverAuth** only; the control plane's own
  certificate carries **clientAuth** only and the common name `adguard-admin`.
  An agent refuses any connection that does not present a certificate chaining
  to the CA with that usage and name. A compromised host therefore cannot pose
  as the control plane to other hosts.
- Agent certificates are valid for a year and are **renewed automatically** by
  the control plane when fewer than 120 days remain (the agent generates a new
  key; the control plane signs and installs the new certificate without a
  restart). **Renew certificate** on the Hosts page does the same on demand.
- The agent runs as root on the host, because it manages Docker, systemd and
  files under `/etc`. Its network surface is the one mTLS port. Everything it
  generates locally (dnsdist API key and console key, VRRP password) stays in
  files with mode 0600 on the host.

## Keeping agents current

The control plane ships the agent build it was released with (the Hosts page
header shows the version). When a host reports a different version, the
control plane asks it to update itself: it hands the agent the download URL
and the SHA-256 over the mutual-TLS channel, the agent fetches the binary,
verifies the checksum, replaces itself and exits, and systemd restarts it on
the new build. AdGuard and the balancer keep running throughout; the host
shows a brief gap in its status (one reconcile cycle reads it as offline)
and comes back with the new version.

The version is the last commit that changed the agent itself, not the image
build, so deploying a control plane whose image carries the same agent code
restarts nothing on the hosts.

This is on by default (`AGENT_AUTO_UPDATE`); a refused or failed attempt is
shown on the row and retried after `AGENT_UPDATE_RETRY_MINUTES`. **Update
agent** in the row menu pushes it immediately. Hosts without systemd get the
new binary but have to be restarted by hand, which the row's message says.

## Reinstalling AdGuard on a host

A host that already ran AdGuard before the agent arrived keeps its old
configuration volume, including its old admin password, and the agent reports
`credentials rejected; the instance was configured before this agent managed
it` rather than guessing. **Reinstall AdGuard (wipe)** in the Servers row menu
(admin only, audit-logged) removes that instance's container and volumes, or
the native install's configuration and data, and re-runs the first-run setup
with the control plane's credentials. The instance's own query log and
statistics on that host are lost; the records, settings and filtering you
manage here are re-applied on the next reconcile pass.

## The Hosts page

| Column | Meaning |
|---|---|
| Status | `online` (last pass succeeded), `offline` (unreachable), `error` (reachable but a call failed), `unknown` (never contacted). |
| Roles | `adguard`, `dnsdist`, as badges. |
| Agent | Agent version and OS/arch. |
| Load / Memory / Disk | From the last health report. |
| Certificate | Days until the agent certificate expires. |

Row actions: **Refresh** (contact the host now), **Logs**, **Restart service**,
**Renew certificate**, and **Delete** (admin). Deleting a host that still has a
server or balancer is refused; **force** removes its balancers and turns its
servers into unmanaged entries you can delete or re-point.

## Files on a host

| Path | Content |
|---|---|
| `/usr/local/bin/adguard-admin-agent` | the binary |
| `/etc/systemd/system/adguard-admin-agent.service` | the service |
| `/etc/adguard-admin-agent/` | `agent.json`, `agent.key`, `agent.crt`, `ca.crt` |
| `/var/lib/adguard-admin-agent/` | last desired state per role, rendered dnsdist config, drained backends |
| `/etc/keepalived/keepalived.conf`, `/etc/sysctl.d/90-adguard-admin-ipvs.conf`, `/etc/modules-load.d/adguard-admin-ipvs.conf` | rendered by the keepalived and ipvs_backend roles |

To remove a host by hand: `systemctl disable --now adguard-admin-agent`, delete
the paths above, and delete the host in the UI. The AdGuard and dnsdist
containers it created are left running until you remove them.
