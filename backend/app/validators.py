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


# --------------------------------------------------------------------------- #
# Load-balancer and VRRP values. These are rendered by the agent into dnsdist's
# Lua config and keepalived's config, so they are validated here as well as on
# the box.
# --------------------------------------------------------------------------- #
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
_IMAGE_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*(?::[A-Za-z0-9_.-]{1,128})?(?:@sha256:[a-f0-9]{64})?$")
_BACKEND_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def validate_cidr(value: str, *, field: str = "cidr") -> str:
    """An IPv4/IPv6 network in CIDR form (a bare address gets a host prefix)."""
    if value is None:
        raise ValidationError(f"{field} is required")
    value = value.strip()
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValidationError(f"{field} must be an IP network in CIDR form (got {value!r})") from exc
    return str(net)


def validate_vip(value: str | None, *, field: str = "vip") -> str | None:
    """A virtual IP with its prefix, e.g. 10.0.0.53/24. Empty clears it."""
    if value is None or not value.strip():
        return None
    value = value.strip()
    if "/" not in value:
        raise ValidationError(f"{field} must include a prefix length, e.g. 10.0.0.53/24")
    try:
        iface = ipaddress.ip_interface(value)
    except ValueError as exc:
        raise ValidationError(f"{field} must be an IP address with prefix (got {value!r})") from exc
    if iface.ip.is_unspecified or iface.ip.is_loopback or iface.ip.is_multicast:
        raise ValidationError(f"{field} must be a unicast address")
    return str(iface)


def validate_router_id(value: int | None, *, field: str = "vrrp_router_id") -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or not (1 <= value <= 255):
        raise ValidationError(f"{field} must be between 1 and 255")
    return value


def validate_priority(value: int, *, field: str = "vrrp_priority") -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not (1 <= value <= 254):
        raise ValidationError(f"{field} must be between 1 and 254")
    return value


def validate_interface(value: str, *, field: str = "interface") -> str:
    value = (value or "").strip()
    if value and not _IFACE_RE.match(value):
        raise ValidationError(f"{field} must be an interface name like eth0")
    return value


def validate_listen_address(value: str, *, field: str = "listen address") -> str:
    """host:port for a dnsdist listener; IPv6 literals bracketed."""
    value = (value or "").strip()
    if _CONTROL_CHARS_RE.search(value) or not value:
        raise ValidationError(f"{field} is required")
    host, port = value, 53
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            raise ValidationError(f"{field} has an unterminated IPv6 literal")
        host = value[1:end]
        rest = value[end + 1:]
        if rest:
            if not rest.startswith(":"):
                raise ValidationError(f"{field} must look like [addr]:port")
            port = _int_port(rest[1:], field)
    elif value.count(":") == 1:
        host, port_s = value.split(":", 1)
        port = _int_port(port_s, field)
    elif value.count(":") > 1:
        host = value  # bare IPv6, default port
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValidationError(f"{field} must be an IP address (got {host!r})") from exc
    return f"{format_host_port(str(ip), port)}"


def _int_port(text: str, field: str) -> int:
    try:
        port = int(text)
    except ValueError as exc:
        raise ValidationError(f"{field} has a non-numeric port") from exc
    return validate_port(port, field=f"{field} port")


def validate_image_ref(value: str, *, field: str = "image") -> str:
    value = (value or "").strip()
    if not _IMAGE_RE.match(value) or len(value) > 255:
        raise ValidationError(f"{field} must be a container image reference like repo/name:tag")
    return value


def validate_backend_name(value: str, *, field: str = "backend name") -> str:
    value = (value or "").strip()
    if not _BACKEND_NAME_RE.match(value):
        raise ValidationError(f"{field} must match [A-Za-z0-9_.-]{{1,64}}")
    return value


def backend_name_for(server_name: str, server_id: int) -> str:
    """A dnsdist backend name derived from a server: safe charset, unique by id."""
    base = re.sub(r"[^A-Za-z0-9_.-]+", "-", (server_name or "").strip()).strip("-.") or "server"
    return f"{base[:50]}-{server_id}"
