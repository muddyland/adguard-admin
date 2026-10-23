"""The agent binaries shipped with this control plane, and their manifest.

Kept apart from the router so the reconcile loop can ask "which agent version
do we ship?" without importing the HTTP layer.
"""
from __future__ import annotations

import hashlib
import threading
from pathlib import Path

from .config import settings

ARCHES = ("amd64", "arm64", "arm")
_lock = threading.Lock()
_cache: tuple[tuple, dict] | None = None


def bin_dir() -> Path:
    return Path(settings.agent_bin_dir)


def binary_path(arch: str) -> Path:
    return bin_dir() / f"adguard-admin-agent-linux-{arch}"


def build_manifest() -> dict:
    """Checksums of the shipped binaries, recomputed only when a file changes."""
    global _cache
    entries = []
    for arch in ARCHES:
        p = binary_path(arch)
        try:
            st = p.stat()
        except OSError:
            continue
        entries.append((arch, st.st_mtime_ns, st.st_size))
    key = tuple(entries)
    with _lock:
        if _cache and _cache[0] == key:
            return _cache[1]
    files = {}
    for arch, _mtime, size in entries:
        h = hashlib.sha256()
        with open(binary_path(arch), "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        files[f"linux/{arch}"] = {"sha256": h.hexdigest(), "size": size}
    version = "unknown"
    try:
        version = (bin_dir() / "VERSION").read_text().strip() or version
    except OSError:
        pass
    manifest = {"version": version, "files": files}
    with _lock:
        _cache = (key, manifest)
    return manifest


def shipped_version() -> str | None:
    """The agent version this control plane can hand out, or None."""
    m = build_manifest()
    if not m["files"] or m["version"] in ("", "unknown", "dev"):
        return None
    return m["version"]


def update_for(agent_arch: str | None) -> tuple[str, str, str] | None:
    """(version, download URL, sha256) for an agent of that arch, or None."""
    m = build_manifest()
    version = shipped_version()
    arch = (agent_arch or "").strip()
    entry = m["files"].get(f"linux/{arch}")
    if version is None or entry is None:
        return None
    base = settings.public_base_url.rstrip("/")
    return version, f"{base}/api/agents/download/linux/{arch}", entry["sha256"]
