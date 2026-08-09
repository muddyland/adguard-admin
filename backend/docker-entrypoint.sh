#!/bin/sh
# Start the app as an unprivileged user, repairing the data volume's ownership
# first if we still have the privileges to do so.
#
# Why this exists: the image used to run as root, so any volume created by an
# older build contains root-owned files. Switching to a non-root user made those
# files unwritable, and SQLite reports that as the distinctly unhelpful
# "attempt to write a readonly database". Rather than make every existing
# deployment run a manual chown, we fix it on the way up.
#
# The application itself never runs as root: whichever path we take below, the
# final exec lands on APP_UID.
set -eu

APP_UID=10001
APP_GID=10001
DATA_DIR="${DATA_DIR:-/data}"

log() { printf '%s entrypoint: %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }

writable_by_app() {
    # Runs a probe as the target user; the shell's own -w test would answer for
    # whoever is running this script, which may still be root.
    setpriv --reuid="$APP_UID" --regid="$APP_GID" --clear-groups \
        sh -c "test -w '$DATA_DIR' && touch '$DATA_DIR/.write-probe' 2>/dev/null && rm -f '$DATA_DIR/.write-probe'" \
        2>/dev/null
}

if [ "$(id -u)" = "0" ]; then
    mkdir -p "$DATA_DIR"
    if ! writable_by_app; then
        log "$DATA_DIR is not writable by uid $APP_UID; taking ownership"
        if chown -R "$APP_UID:$APP_GID" "$DATA_DIR"; then
            log "ownership of $DATA_DIR updated"
        else
            log "WARNING: could not chown $DATA_DIR (missing CAP_CHOWN?)."
            log "WARNING: run: docker compose run --rm --user root --entrypoint sh app -c 'chown -R $APP_UID:$APP_GID /data'"
        fi
    fi
    # Drop privileges for the actual application.
    exec setpriv --reuid="$APP_UID" --regid="$APP_GID" --clear-groups "$@"
fi

# Already unprivileged (e.g. an explicit `user:` override in compose). We cannot
# repair anything from here, so fail with something actionable instead of
# letting SQLite surface it as a readonly-database error deep in startup.
if [ ! -w "$DATA_DIR" ]; then
    log "FATAL: $DATA_DIR is not writable by uid $(id -u)."
    log "The data volume is probably still owned by root from an older build."
    log "Fix it with:"
    log "  docker compose run --rm --user root --entrypoint sh app -c 'chown -R $APP_UID:$APP_GID /data'"
    exit 1
fi

exec "$@"
