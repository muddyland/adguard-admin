r"""The on-box updater for AdGuard Home running in Docker.

A container cannot replace the image it is running from, and this app has no
remote-execution channel to the Docker host, so container upgrades cannot be
driven from the control plane the way bare-metal ones are (see app.updater).
What ships instead is a small installer script, served unauthenticated at
`GET /api/updates/docker-agent.sh`:

    curl -fsSL https://<admin-url>/api/updates/docker-agent.sh | sudo bash

It installs `/usr/local/bin/adguard-home-update` plus a daily systemd timer (or
a cron job where systemd is absent). The updater pulls the image the container
was created from, and if the digest moved, recreates the container with the same
configuration — keeping the *named volumes*, so AdGuard's config and data
survive untouched.

The script holds no secrets and is identical for every install, so it is served
without authentication; provisioning simply pipes the same URL into bash.

Two deliberate choices in the updater:

* **Compose-managed containers are handed back to Compose.** Recreating one with
  a bare `docker run` would orphan it from its project. If the container carries
  Compose labels and the Compose plugin is present, it runs `compose up -d`.
* **The previous container is kept until the new one is healthy**, renamed
  rather than removed, so a bad image rolls straight back instead of leaving the
  network without DNS.
"""
from __future__ import annotations

# Kept as one static, dependency-free script: it is piped into a root shell on
# machines this app has never seen, so there is nothing interpolated into it.
AGENT_SCRIPT = r"""#!/usr/bin/env bash
# AdGuard Admin — installs the on-box auto-updater for a dockerised AdGuard Home.
#
#   curl -fsSL <admin-url>/api/updates/docker-agent.sh | sudo bash
#
# Environment:
#   CONTAINER=adguardhome     name of the AdGuard Home container to keep updated
#   SCHEDULE=daily            systemd OnCalendar expression (or 'daily'/'weekly')
#   UNINSTALL=true            remove the updater and its timer
set -euo pipefail

CONTAINER="${CONTAINER:-adguardhome}"
SCHEDULE="${SCHEDULE:-daily}"
UNINSTALL="${UNINSTALL:-false}"

BIN=/usr/local/bin/adguard-home-update
CONF=/etc/adguard-home-update.conf
UNIT=/etc/systemd/system/adguard-home-update.service
TIMER=/etc/systemd/system/adguard-home-update.timer
CRON=/etc/cron.d/adguard-home-update

green(){ printf '\033[0;32m[adguard-update]\033[0m %s\n' "$*"; }
red(){ printf '\033[0;31m[adguard-update]\033[0m %s\n' "$*" >&2; }

[ "$(id -u)" -eq 0 ] || { red "Please run as root (pipe the one-liner into 'sudo bash')."; exit 1; }

have_systemd(){ command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; }

if [ "$UNINSTALL" = "true" ]; then
  green "Removing the AdGuard Home auto-updater..."
  if have_systemd; then
    systemctl disable --now adguard-home-update.timer >/dev/null 2>&1 || true
    rm -f "$UNIT" "$TIMER"
    systemctl daemon-reload
  fi
  rm -f "$CRON" "$BIN" "$CONF"
  green "Removed."
  exit 0
fi

command -v docker >/dev/null 2>&1 || { red "docker is not installed on this host."; exit 1; }
docker inspect "$CONTAINER" >/dev/null 2>&1 || {
  red "No container named '$CONTAINER'. Set CONTAINER=<name> and re-run:"
  red "  curl -fsSL <admin-url>/api/updates/docker-agent.sh | sudo CONTAINER=my-adguard bash"
  exit 1
}

green "Installing $BIN (container: $CONTAINER)..."
printf 'CONTAINER=%s\n' "$CONTAINER" > "$CONF"
chmod 0644 "$CONF"

cat > "$BIN" <<'UPDATER'
#!/usr/bin/env bash
# Pull the image this AdGuard Home container runs and recreate it if it moved.
# Installed by AdGuard Admin. Named volumes are preserved, so configuration and
# statistics survive the upgrade.
set -euo pipefail

[ -r /etc/adguard-home-update.conf ] && . /etc/adguard-home-update.conf
CONTAINER="${CONTAINER:-adguardhome}"
BACKUP="${CONTAINER}-preupdate"
LOCK=/var/lock/adguard-home-update.lock

log(){ printf '%s adguard-home-update: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }

# Never let two runs (timer + a manual invocation) race over the same container.
if command -v flock >/dev/null 2>&1; then
  exec 9>"$LOCK"
  flock -n 9 || { log "another update run is in progress; exiting"; exit 0; }
fi

docker inspect "$CONTAINER" >/dev/null 2>&1 || { log "container '$CONTAINER' not found"; exit 1; }

IMAGE="$(docker inspect -f '{{.Config.Image}}' "$CONTAINER")"
OLD_IMAGE_ID="$(docker inspect -f '{{.Image}}' "$CONTAINER")"

# What the container carries beyond the image's own defaults. All read *before*
# the pull, while OLD_IMAGE_ID still describes the image it is running.
list_of(){ docker "$1" inspect -f "{{range .Config.$2}}{{println .}}{{end}}" "$3" 2>/dev/null | sed '/^$/d' || true; }
labels_of(){ docker "$1" inspect -f '{{range $k, $v := .Config.Labels}}{{printf "%s=%s" $k $v | println}}{{end}}' "$2" 2>/dev/null | sed '/^$/d' || true; }

mapfile -t IMAGE_ENV < <(list_of image Env "$OLD_IMAGE_ID")
mapfile -t CONTAINER_ENV < <(list_of container Env "$CONTAINER")
mapfile -t IMAGE_CMD < <(list_of image Cmd "$OLD_IMAGE_ID")
mapfile -t CONTAINER_CMD < <(list_of container Cmd "$CONTAINER")
mapfile -t IMAGE_ENTRYPOINT < <(list_of image Entrypoint "$OLD_IMAGE_ID")
mapfile -t CONTAINER_ENTRYPOINT < <(list_of container Entrypoint "$CONTAINER")
mapfile -t IMAGE_LABELS < <(labels_of image "$OLD_IMAGE_ID")
mapfile -t CONTAINER_LABELS < <(labels_of container "$CONTAINER")
IMAGE_USER="$(docker image inspect -f '{{.Config.User}}' "$OLD_IMAGE_ID" 2>/dev/null || true)"
CONTAINER_USER="$(docker inspect -f '{{.Config.User}}' "$CONTAINER" 2>/dev/null || true)"

log "pulling $IMAGE"
docker pull "$IMAGE" >/dev/null
NEW_IMAGE_ID="$(docker image inspect -f '{{.Id}}' "$IMAGE")"

if [ "$NEW_IMAGE_ID" = "$OLD_IMAGE_ID" ]; then
  log "already up to date ($IMAGE)"
  exit 0
fi

log "new image for $IMAGE; recreating $CONTAINER"

# Compose owns its containers: recreating one by hand would orphan it from the
# project. Hand it back to Compose when we can.
COMPOSE_PROJECT="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$CONTAINER" 2>/dev/null || true)"
COMPOSE_DIR="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$CONTAINER" 2>/dev/null || true)"
COMPOSE_SERVICE="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.service"}}' "$CONTAINER" 2>/dev/null || true)"
if [ -n "$COMPOSE_PROJECT" ] && [ -n "$COMPOSE_DIR" ] && [ -d "$COMPOSE_DIR" ] && docker compose version >/dev/null 2>&1; then
  log "container is managed by docker compose (project '$COMPOSE_PROJECT'); using compose up -d"
  cd "$COMPOSE_DIR"
  docker compose up -d ${COMPOSE_SERVICE:+"$COMPOSE_SERVICE"}
  log "updated via docker compose"
  exit 0
fi

# Rebuild the run arguments from the live container: ports, mounts, restart
# policy, network, added capabilities and any environment the image didn't set.
# Every template emits one token per line, so values containing spaces survive.
TPL='{{range $p, $conf := .HostConfig.PortBindings}}{{range $conf}}{{println "-p"}}{{if .HostIp}}{{printf "%s:%s:%s" .HostIp .HostPort $p | println}}{{else}}{{printf "%s:%s" .HostPort $p | println}}{{end}}{{end}}{{end}}'
TPL+='{{range .Mounts}}{{println "-v"}}{{if eq .Type "volume"}}{{printf "%s:%s" .Name .Destination}}{{else}}{{printf "%s:%s" .Source .Destination}}{{end}}{{if not .RW}}:ro{{end}}{{println ""}}{{end}}'
TPL+='{{with .HostConfig.RestartPolicy}}{{if .Name}}{{println "--restart"}}{{println .Name}}{{end}}{{end}}'
TPL+='{{with .HostConfig.NetworkMode}}{{if ne (printf "%s" .) "default"}}{{println "--network"}}{{printf "%s" . | println}}{{end}}{{end}}'
TPL+='{{range .HostConfig.CapAdd}}{{println "--cap-add"}}{{println .}}{{end}}'
TPL+='{{if .HostConfig.Privileged}}{{println "--privileged"}}{{end}}'

# `docker inspect -f` adds its own trailing newline on top of ours, which would
# otherwise reach `docker run` as an empty argument.
ARGS=()
mapfile -t ARGS < <(docker inspect -f "$TPL" "$CONTAINER" | sed '/^$/d')

# Pass through only what the image does not already provide, so a container
# started as a plain `docker run adguard/adguardhome` is recreated just as plain.
for env in ${CONTAINER_ENV[@]+"${CONTAINER_ENV[@]}"}; do
  inherited=false
  for image_env in ${IMAGE_ENV[@]+"${IMAGE_ENV[@]}"}; do
    [ "$env" = "$image_env" ] && { inherited=true; break; }
  done
  $inherited || ARGS+=(-e "$env")
done

for label in ${CONTAINER_LABELS[@]+"${CONTAINER_LABELS[@]}"}; do
  inherited=false
  for image_label in ${IMAGE_LABELS[@]+"${IMAGE_LABELS[@]}"}; do
    [ "$label" = "$image_label" ] && { inherited=true; break; }
  done
  $inherited || ARGS+=(-l "$label")
done

[ -n "$CONTAINER_USER" ] && [ "$CONTAINER_USER" != "$IMAGE_USER" ] && ARGS+=(--user "$CONTAINER_USER")

# A custom entrypoint or command must be carried over, or the container comes
# back running the image default — which for most images means it exits at once.
CMD_ARGS=()
if [ "${CONTAINER_ENTRYPOINT[*]-}" != "${IMAGE_ENTRYPOINT[*]-}" ] && [ ${#CONTAINER_ENTRYPOINT[@]} -gt 0 ]; then
  ARGS+=(--entrypoint "${CONTAINER_ENTRYPOINT[0]}")
  # `docker run` takes a single-string entrypoint, so any further elements have
  # to travel as leading command arguments.
  CMD_ARGS+=("${CONTAINER_ENTRYPOINT[@]:1}")
fi
if [ "${CONTAINER_CMD[*]-}" != "${IMAGE_CMD[*]-}" ]; then
  CMD_ARGS+=(${CONTAINER_CMD[@]+"${CONTAINER_CMD[@]}"})
fi

docker rm -f "$BACKUP" >/dev/null 2>&1 || true
docker stop "$CONTAINER" >/dev/null
docker rename "$CONTAINER" "$BACKUP"

rollback() {
  log "ERROR: the new container did not come up; rolling back to the previous image"
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker rename "$BACKUP" "$CONTAINER"
  docker start "$CONTAINER" >/dev/null
  log "rolled back"
  exit 1
}

docker run -d --name "$CONTAINER" ${ARGS[@]+"${ARGS[@]}"} "$IMAGE" ${CMD_ARGS[@]+"${CMD_ARGS[@]}"} >/dev/null || rollback

# Give it a moment to crash, if it is going to.
sleep 10
[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null || echo false)" = "true" ] || rollback

docker rm "$BACKUP" >/dev/null 2>&1 || true
NEW_VERSION="$(docker inspect -f '{{index .Config.Labels "org.opencontainers.image.version"}}' "$CONTAINER" 2>/dev/null || true)"
log "updated $CONTAINER to $IMAGE ${NEW_VERSION:+($NEW_VERSION)}"
UPDATER
chmod 0755 "$BIN"

if have_systemd; then
  green "Installing the systemd timer (schedule: $SCHEDULE)..."
  cat > "$UNIT" <<UNITEOF
[Unit]
Description=Update the AdGuard Home container
Documentation=https://github.com/AdguardTeam/AdGuardHome
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=$BIN
UNITEOF
  cat > "$TIMER" <<TIMEREOF
[Unit]
Description=Daily AdGuard Home container update

[Timer]
OnCalendar=$SCHEDULE
# Spread the load and avoid every box in a fleet restarting at the same second.
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
TIMEREOF
  systemctl daemon-reload
  systemctl enable --now adguard-home-update.timer >/dev/null
  green "Enabled. Next run: $(systemctl show -p NextElapseUSecRealtime --value adguard-home-update.timer 2>/dev/null || echo unknown)"
  green "Run it now with:  systemctl start adguard-home-update.service"
else
  green "systemd not available — installing a cron job instead."
  printf '# Installed by AdGuard Admin\n17 4 * * * root %s >> /var/log/adguard-home-update.log 2>&1\n' "$BIN" > "$CRON"
  chmod 0644 "$CRON"
  green "Installed at $CRON (04:17 daily, logs to /var/log/adguard-home-update.log)."
fi

green "Done. '$CONTAINER' will be kept up to date."
green "Update now with:  $BIN"
"""


def render_agent_script() -> str:
    """The installer script, exactly as served."""
    return AGENT_SCRIPT
