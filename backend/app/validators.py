"""Shared input validation for values that reach a shell, a URL, or a cert SAN.

Provisioning interpolates operator-supplied strings into a bash script that runs
as root on the target host, and into the URL the reconcile loop later connects
to. Everything that crosses one of those boundaries is validated here first;
quoting alone is not enough when a value can also carry newlines.
"""
from __future__ import annotations

import ipaddress
import re

# RFC 1123 hostname: dot-separated labels of alphanumerics and hyphens, each
# 1-63 chars, not starting or ending with a hyphen.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)

# Printable, single-line, no shell metacharacters that survive quoting badly.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

MAX_NAME_LENGTH = 100


class ValidationError(ValueError):
    """Raised for a value that must never reach a shell or a URL."""


def validate_display_name(value: str, *, field: str = "name") -> str:
    """A human-readable name that is also embedded in the generated install script.

    Rejects control characters (a newline would break out of the shell comment
    the name is rendered into) and over-long values.
    """
    if value is None:
        raise ValidationError(f"{field} is required")
    value = value.strip()
    if not value:
        raise ValidationError(f"{field} must not be empty")
    if len(value) > MAX_NAME_LENGTH:
        raise ValidationError(f"{field} must be at most {MAX_NAME_LENGTH} characters")
    if _CONTROL_CHARS_RE.search(value):
        raise ValidationError(f"{field} must not contain control characters")
    return value


def is_valid_host(value: str) -> bool:
    """True for a bare IPv4/IPv6 literal or an RFC 1123 hostname."""
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(value))


def validate_host(value: str, *, field: str = "connect_address") -> str:
    """A hostname or IP that is interpolated into a URL, a cert SAN and a shell script."""
    if value is None:
        raise ValidationError(f"{field} is required")
    value = value.strip()
    if not is_valid_host(value):
        raise ValidationError(
            f"{field} must be a hostname or IP address (got {value!r})"
        )
    return value


def format_host_port(host: str, port: int) -> str:
    """Join a host and port for a URL, bracketing IPv6 literals."""
    try:
        if isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address):
            return f"[{host}]:{port}"
    except ValueError:
        pass
    return f"{host}:{port}"


def validate_server_url(value: str, *, field: str = "url") -> str:
    """An http(s) URL for an AdGuard instance we will authenticate to and proxy."""
    import urllib.parse

    if value is None:
        raise ValidationError(f"{field} is required")
    value = value.strip().rstrip("/")
    if _CONTROL_CHARS_RE.search(value):
        raise ValidationError(f"{field} must not contain control characters")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in ("http", "https"):
        raise ValidationError(f"{field} must start with http:// or https://")
    if not parsed.hostname:
        raise ValidationError(f"{field} must include a host")
    if not is_valid_host(parsed.hostname):
        raise ValidationError(f"{field} has an invalid host ({parsed.hostname!r})")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValidationError(f"{field} has an invalid port: {exc}") from exc
    if port is not None:
        validate_port(port, field=f"{field} port")
    return value


def validate_port(value: int, *, field: str = "port") -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(f"{field} must be an integer")
    if not (1 <= value <= 65535):
        raise ValidationError(f"{field} must be between 1 and 65535")
    return value
