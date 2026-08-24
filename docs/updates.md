# Updates

AdGuard Admin can keep the **AdGuard Home installations themselves** up to date —
the binary on a bare-metal box, the image behind a container — not just their DNS
configuration. The **Updates** page shows every server's installed version, what's
available, and who is responsible for installing it.

## Who performs the upgrade

This is the one thing worth understanding before turning anything on, because it
is not a preference — it follows from how each install works.

| Install method | Upgraded by | How |
|---|---|---|
| **Bare-metal** (native install) | **AdGuard Admin** | Calls AdGuard Home's own control API (`POST /control/update`) — the same thing its "Update now" button does. The binary is replaced and the service restarts. |
| **Docker** | **The on-box updater** | A container cannot replace the image it is running from, so AdGuard reports `can_autoupdate: false` and this app will not try. A small updater on the Docker host pulls the image and recreates the container instead. |

The admin app has no remote shell on your servers — only AdGuard's HTTP API — so
for containers there is nothing it *could* run. It records those servers as
**on-box updater** and simply observes the version change afterwards.

Set each server's install method under **Servers → Edit → How AdGuard Home is
installed here**. [Provisioned](provisioning.md) servers already know theirs.

## Turning it on

Automatic updates are **off per server** by default. Nothing upgrades until you
opt a server in, because an upgrade restarts AdGuard Home — and while it
restarts, everything using it for DNS stops resolving.

1. Go to **Updates** (or **Servers → Edit**) and tick **auto-update** for the
   servers you want kept current.
2. Optionally set a maintenance window with `AUTO_UPDATE_WINDOW` (see the
   [configuration reference](configuration.md#automatic-updates)).
3. For Docker servers, install the on-box updater — see below.

`AUTO_UPDATE_ENABLED=false` switches the whole scheduler off without touching
per-server flags; the manual buttons keep working.

> **Keep a fallback resolver.** Upgrades roll **one server at a time**
> (`AUTO_UPDATE_MAX_CONCURRENCY`, default 1) so the fleet never restarts at once.
> Even so, clients pointed at a single AdGuard server will see a short DNS outage
> while it restarts. Give clients a second server, or stagger which servers have
> auto-update on.

## The schedule

The updater wakes every `AUTO_UPDATE_INTERVAL_SECONDS` (default 1h) and upgrades
the servers that are due. A server is due when all of these hold:

- it is **enabled** and has **auto-update** on,
- AdGuard reports a **newer version** than the one installed,
- it is not in an **auth/rate-limit cooldown** (an upgrade means more
  authenticated calls, which is the last thing a locked-out server needs),
- the current time is inside `AUTO_UPDATE_WINDOW`, if one is set,
- and its **last attempt** did not fail within the past `AUTO_UPDATE_RETRY_HOURS`.

The Updates page shows the reason next to any server that is opted in but not
currently due.

**Update now** (per server, or *Update all eligible*) ignores the window and the
retry backoff — you are standing right there. It still refuses to "upgrade" a
server that has nothing to install.

## What an upgrade looks like

1. The app re-checks the version *with the server itself* (`recheck_now`), rather
   than trusting the fleet view, which can be a cycle stale.
2. If AdGuard says it cannot self-upgrade, the server is marked **on-box
   updater** and left alone until a *newer* release appears.
3. Otherwise it calls `POST /control/update` and waits.
4. AdGuard restarts, so the reply to that call is usually lost — a dropped
   connection here means the upgrade *started*, and only a real HTTP error means
   it was refused.
5. The app polls the server until it reports a different version, up to
   `AUTO_UPDATE_RESTART_TIMEOUT_SECONDS` (default 5 min). A server that never
   comes back is recorded as **failed**, with the version it was upgrading to.

Reconciliation is locked out of a server for the duration, so a sync pass is
never mid-conversation with a box that is restarting under it.

## Docker servers: the on-box updater

Run this on any Docker host running AdGuard Home:

```bash
curl -fsSL "https://<your-admin-url>/api/updates/docker-agent.sh" | sudo bash
```

It installs `/usr/local/bin/adguard-home-update` and a **daily systemd timer**
(with up to an hour of random delay, so a fleet doesn't restart in lockstep). On
hosts without systemd it installs a cron job instead. The **Updates** page has
the command ready to copy, and lists the servers that need it.

| Variable | Default | Purpose |
|---|---|---|
| `CONTAINER` | `adguardhome` | Name of the container to keep updated. |
| `SCHEDULE` | `daily` | Any systemd `OnCalendar` expression. |
| `UNINSTALL` | `false` | Set to `true` to remove the updater and its timer. |

```bash
# A container by another name:
curl -fsSL "https://<admin-url>/api/updates/docker-agent.sh" | sudo CONTAINER=adguard bash
# Remove it again:
curl -fsSL "https://<admin-url>/api/updates/docker-agent.sh" | sudo UNINSTALL=true bash
```

Each run:

1. pulls the image the container was created from,
2. exits if the digest hasn't moved,
3. hands the job to **Docker Compose** if the container belongs to a Compose
   project — recreating it by hand would orphan it from its project,
4. otherwise recreates it with the same ports, mounts, restart policy, network,
   capabilities, environment, labels and command, and
5. **rolls back** to the previous container if the new one doesn't come up.

Your AdGuard configuration and statistics live in its **named volumes**, which
are reused untouched — that is what makes recreating the container safe.

Because the image runs with `--no-check-update`, a dockerised server reports no
version information to this app at all — the Updates page shows **on-box updater**
rather than a release number, and the new version appears after the updater has
run and the next sync has picked it up. This is why the install method matters:
it is what tells the app to expect that, instead of treating the silence as a
server that has fallen behind.

Run it by hand any time:

```bash
sudo /usr/local/bin/adguard-home-update      # logs to stdout / journald
systemctl start adguard-home-update.service  # or via the timer's unit
journalctl -u adguard-home-update            # what the last runs did
```

The script is fixed and holds no secrets, so it is served without
authentication — it has to be fetchable by `curl | bash` on a machine that has no
credentials for this app, exactly like the provisioning one-liner.

### Limits worth knowing

- It needs **bash** (not just `sh`) and Docker on the host.
- Recreating carries over ports, mounts, restart policy, network mode,
  capabilities, environment, labels and the command. Exotic runtime flags
  (devices, ulimits, sysctls, custom DNS) are **not** reconstructed — if you use
  those, run AdGuard Home under Compose and the updater will defer to it.
- It follows the **tag** the container was created with. A container pinned to
  `adguard/adguardhome:v0.107.60` will never move; use `:latest` to track
  releases.

## Provisioning

When you [provision a server](provisioning.md), tick **Keep AdGuard Home up to
date automatically**:

- **Docker** — the install script also installs the on-box updater, and the
  registered server is marked as a Docker install.
- **Bare-metal** — the registered server is opted in, and this app upgrades it on
  the schedule above.

## API

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/api/updates` | viewer | Fleet update posture and the schedule |
| POST | `/api/updates/check` | editor | Force a version re-check (`?server_id=` for one) |
| POST | `/api/updates/run` | editor | Update every eligible server (`?force=true` ignores the window) |
| POST | `/api/updates/{id}/run` | editor | Update one server now |
| GET | `/api/updates/docker-agent.sh` | — | The on-box updater installer |

## Troubleshooting

**"AdGuard Home x.y.z is available, but this instance reports it cannot upgrade
itself."** — AdGuard sets `can_autoupdate: false` for a container, a package
install (`apt`/`brew`), or a binary it cannot overwrite. Install the on-box
updater, or update it the way it was installed.

**"…did not come back within 300s."** — The upgrade was started but the server
never reported a new version. Check the box before retrying; the app backs off
for `AUTO_UPDATE_RETRY_HOURS`. Raise
`AUTO_UPDATE_RESTART_TIMEOUT_SECONDS` for a slow host.

**The Updates page says *checks disabled*.** — AdGuard Home has its own
*Automatically check for updates* setting (Settings → General settings). When it
is off, `version.json` answers `{"disabled": true}` and the server never reports
a new release — which is not the same as being current, so the app says so rather
than showing it as up to date. Turn the setting on, or remove `--no-check-update`
from however that server is started.

**A Docker server shows *on-box updater* and no version information.** — Expected,
and there is nothing to switch on. The official image starts AdGuard Home with
`--no-check-update`, and that flag **overrides `check_update` in the config**, so
the setting is absent from that server's UI and writing it into `AdGuardHome.yaml`
has no effect (AdGuard drops the key on the next restart). It is deliberate:
a container cannot replace its own image, so the version check would only ever
report an upgrade it could not perform. The [on-box updater](#docker-servers-the-on-box-updater)
keeps the container current, and its new version appears here on the next sync
after the updater runs.

**A server keeps showing an update that never installs.** — Check its install
method. A Docker server without the on-box updater sits at **on-box updater**
forever, by design.

**The version doesn't change after the on-box updater runs.** — Check the tag:
`docker inspect -f '{{.Config.Image}}' adguardhome`. A pinned version tag never
moves. Then check `journalctl -u adguard-home-update`.
