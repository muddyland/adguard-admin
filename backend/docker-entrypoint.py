"""Start the app as an unprivileged user, repairing the data volume first.

Why this exists: the image used to run as root, so any volume created by an
older build contains root-owned files. Switching to a non-root user made those
files unwritable, and SQLite reports that as the distinctly unhelpful "attempt
to write a readonly database". Rather than make every existing deployment run
a manual chown, we fix it on the way up.

Why Python and not a shell script: the image can be built on a hardened base
that has no shell, no chown and no setpriv, only the interpreter. Everything
below is the standard library, so it runs the same on either base.

The application itself never runs as root. Whichever path we take below, the
final exec lands on APP_UID.
"""
from __future__ import annotations

import os
import sys
import time

APP_UID = 10001
APP_GID = 10001
DATA_DIR = os.environ.get("DATA_DIR", "/data")

# Works on any base, shell or not: the entrypoint runs as root, repairs the
# volume, then execs the given command (a no-op here) as the app user.
FIX_COMMAND = (
    "docker compose run --rm --user root app python -c pass"
)


def log(message: str) -> None:
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    print(f"{stamp} entrypoint: {message}", file=sys.stderr, flush=True)


def drop_privileges() -> None:
    """Become APP_UID:APP_GID with no supplementary groups.

    Order matters: groups and gid first, while we still have the privilege to
    change them, then uid, after which we can't change anything back.
    """
    os.setgroups([])
    os.setgid(APP_GID)
    os.setuid(APP_UID)


def writable_by_app(path: str) -> bool:
    """Probe the directory as the app user, in a forked child.

    os.access() or a test in this process would answer for whoever is running
    the entrypoint, which may still be root, and root can write anything. Only
    a real write by the target uid says what the app will see.
    """
    pid = os.fork()
    if pid == 0:  # child
        ok = False
        try:
            drop_privileges()
            probe = os.path.join(path, ".write-probe")
            with open(probe, "w"):
                pass
            os.unlink(probe)
            ok = True
        except OSError:
            pass
        os._exit(0 if ok else 1)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status) == 0


def chown_tree(root: str, uid: int, gid: int) -> None:
    """`chown -R`, without following symlinks.

    lchown changes a symlink itself rather than its target, and os.walk does
    not descend into symlinked directories, so a link planted in the volume
    can't redirect the chown at files outside it.
    """
    os.lchown(root, uid, gid)
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            os.lchown(os.path.join(dirpath, name), uid, gid)


def main(argv: list[str]) -> int:
    if not argv:
        log("FATAL: no command given")
        return 2

    if os.getuid() == 0:
        os.makedirs(DATA_DIR, exist_ok=True)
        if not writable_by_app(DATA_DIR):
            log(f"{DATA_DIR} is not writable by uid {APP_UID}; taking ownership")
            try:
                chown_tree(DATA_DIR, APP_UID, APP_GID)
                log(f"ownership of {DATA_DIR} updated")
            except OSError as exc:
                log(f"WARNING: could not chown {DATA_DIR}: {exc} (missing CAP_CHOWN?)")
                log(f"WARNING: run: {FIX_COMMAND}")
        try:
            drop_privileges()
        except OSError as exc:
            # Never fall through to running the app as root.
            log(f"FATAL: cannot drop to uid {APP_UID}: {exc}")
            log("FATAL: the container needs CAP_SETUID and CAP_SETGID to start as root")
            return 1
    elif not os.access(DATA_DIR, os.W_OK):
        # Already unprivileged (e.g. an explicit `user:` override in compose).
        # We cannot repair anything from here, so fail with something
        # actionable instead of letting SQLite surface it as a
        # readonly-database error deep in startup.
        log(f"FATAL: {DATA_DIR} is not writable by uid {os.getuid()}.")
        log("The data volume is probably still owned by root from an older build.")
        log("Fix it with:")
        log(f"  {FIX_COMMAND}")
        return 1

    try:
        os.execvp(argv[0], argv)
    except OSError as exc:
        log(f"FATAL: cannot exec {argv[0]!r}: {exc}")
        return 127


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
