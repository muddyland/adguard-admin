from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlalchemy import JSON
from sqlmodel import Field, Relationship, SQLModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Role(str, Enum):
    admin = "admin"      # full control incl. user management
    editor = "editor"    # manage zones/servers/records, trigger sync
    viewer = "viewer"    # read-only


class RecordScope(str, Enum):
    global_ = "global"   # applies to every server in every zone
    zone = "zone"        # applies only to servers in a specific zone


class ConfigScope(str, Enum):
    """Scope for DNS settings (upstreams, forward zones)."""
    global_ = "global"   # every server
    zone = "zone"        # servers in a specific zone
    server = "server"    # a single server


class DnsServerKind(str, Enum):
    """Which AdGuard DNS list a server address belongs to."""
    upstream = "upstream"     # -> upstream_dns
    bootstrap = "bootstrap"   # -> bootstrap_dns
    fallback = "fallback"     # -> fallback_dns
    private = "private"       # -> local_ptr_upstreams (private reverse-DNS resolvers)


class FilterKind(str, Enum):
    """Which AdGuard filtering list a subscription belongs to."""
    blocklist = "blocklist"   # -> filters (whitelist=false): blocks matching domains
    allowlist = "allowlist"   # -> whitelist_filters (whitelist=true): exempts domains


class SyncStatus(str, Enum):
    unknown = "unknown"
    online = "online"
    offline = "offline"
    error = "error"


class InstallMethod(str, Enum):
    docker = "docker"
    bare_metal = "bare_metal"


class ProvisionStatus(str, Enum):
    pending = "pending"      # token issued, install not yet completed
    completed = "completed"  # box installed and registered itself
    revoked = "revoked"      # cancelled before use


class UpdateState(str, Enum):
    """Outcome of the last automatic-update attempt on a server."""
    idle = "idle"                # never attempted, or nothing to do
    running = "running"          # an upgrade is in flight right now
    succeeded = "succeeded"      # the box came back on the new version
    failed = "failed"            # the attempt errored; retried after a backoff
    # AdGuard cannot upgrade itself here (a container, or a read-only install).
    # The box updates itself instead — see the on-box updater in updater.py.
    delegated = "delegated"


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    email: Optional[str] = Field(default=None, index=True)
    hashed_password: Optional[str] = None  # null for OIDC-only accounts
    role: Role = Field(default=Role.viewer)
    is_active: bool = True
    # Subject claim from the OIDC provider (Authentik), links external identity.
    oidc_sub: Optional[str] = Field(default=None, index=True, unique=True)
    created_at: datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- #
# Zones & Servers
# --------------------------------------------------------------------------- #
class Zone(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)      # e.g. "IoT VLAN"
    slug: str = Field(index=True, unique=True)       # e.g. "iot-vlan"
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow)

    servers: list["Server"] = Relationship(back_populates="zone")


class Server(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    url: str                                   # e.g. http://10.0.0.2:3000
    username: Optional[str] = None             # AdGuard Home admin user
    password_enc: Optional[str] = None         # Fernet-encrypted password
    zone_id: Optional[int] = Field(default=None, foreign_key="zone.id", index=True)
    enabled: bool = True
    # Whether to remove un-managed rewrites on this server during reconcile.
    prune: bool = False
    # Opt-in: also reconcile this server's upstream DNS config (upstreams + forward zones).
    manage_upstreams: bool = False
    # Opt-in: also reconcile this server's filtering (blocklists, allowlists, blocked services).
    manage_filtering: bool = False
    # Pinned PEM certificate for verifying TLS to this server (self-signed boxes).
    tls_cert: Optional[str] = None

    # --- Automatic AdGuard Home upgrades ---------------------------------- #
    # Opt-in: keep this server's AdGuard Home on the latest release.
    auto_update: bool = False
    # How AdGuard Home was installed here. Recorded by provisioning; settable by
    # hand for servers added manually. It decides *who* performs the upgrade:
    # a bare-metal box is upgraded by this app over the control API, a container
    # by the on-box updater (a container cannot replace its own image).
    install_method: Optional[InstallMethod] = None
    # Whether AdGuard itself reports that it can self-upgrade (false in Docker).
    can_autoupdate: bool = False
    # AdGuard's version check is switched off on this server (its version.json
    # answers {"disabled": true}), so it will never report a new release. Without
    # this the server looks permanently, and misleadingly, up to date.
    update_check_disabled: bool = False
    update_state: UpdateState = Field(default=UpdateState.idle)
    update_attempted_at: Optional[datetime] = None
    # Target of the last attempt; keyed on so a failure is retried with a backoff
    # and a delegated/unsupported target is not re-attempted every cycle.
    update_attempted_version: Optional[str] = None
    update_completed_at: Optional[datetime] = None
    update_error: Optional[str] = None

    # Health / sync bookkeeping (updated by the reconcile loop)
    status: SyncStatus = Field(default=SyncStatus.unknown)
    version: Optional[str] = None
    latest_version: Optional[str] = None      # newest version AdGuard reports
    update_available: bool = False
    last_seen: Optional[datetime] = None
    last_synced: Optional[datetime] = None
    last_error: Optional[str] = None
    # Set when auth fails / AdGuard rate-limits us; the loop skips the server
    # until this passes so we don't worsen a brute-force lockout.
    cooldown_until: Optional[datetime] = None
    # True once the desired state matches what's on the server.
    in_sync: bool = False

    created_at: datetime = Field(default_factory=utcnow)

    zone: Optional[Zone] = Relationship(back_populates="servers")


# --------------------------------------------------------------------------- #
# DNS records (the source of truth)
# --------------------------------------------------------------------------- #
class DNSRecord(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    domain: str = Field(index=True)            # e.g. nas.home.lan
    answer: str                                 # IP or hostname (CNAME)
    scope: RecordScope = Field(default=RecordScope.global_)
    # One or more zones when scope == zone; empty/ignored for global records.
    zone_ids: list[int] = Field(default_factory=list, sa_type=JSON)
    enabled: bool = True
    description: Optional[str] = None
    # True for records the app auto-maintains (e.g. server hostnames -> IP).
    # These are read-only in the UI and kept in sync by the reconcile loop.
    managed: bool = False
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- #
# DNS settings: upstream servers & per-domain forward zones
# --------------------------------------------------------------------------- #
class Upstream(SQLModel, table=True):
    """A DNS server address for one of AdGuard's lists (upstream / bootstrap /
    fallback / private), scoped global / zone / server."""
    id: Optional[int] = Field(default=None, primary_key=True)
    address: str
    kind: DnsServerKind = Field(default=DnsServerKind.upstream, index=True)
    scope: ConfigScope = Field(default=ConfigScope.global_)
    zone_ids: list[int] = Field(default_factory=list, sa_type=JSON)
    server_id: Optional[int] = Field(default=None, foreign_key="server.id", index=True)
    enabled: bool = True
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow)


class ForwardZone(SQLModel, table=True):
    """Per-domain forwarding: send queries for `domains` to specific `upstreams`.

    Rendered into AdGuard's upstream syntax, e.g. [/internal.lan/]10.0.0.53.
    """
    id: Optional[int] = Field(default=None, primary_key=True)
    # One or more domains, whitespace/comma separated (e.g. "internal.lan corp.lan").
    domains: str
    # One or more upstream addresses, whitespace/comma/newline separated.
    upstreams: str
    scope: ConfigScope = Field(default=ConfigScope.global_)
    zone_ids: list[int] = Field(default_factory=list, sa_type=JSON)
    server_id: Optional[int] = Field(default=None, foreign_key="server.id", index=True)
    enabled: bool = True
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- #
# Filtering: blocklists / allowlists & blocked services
# --------------------------------------------------------------------------- #
class FilterList(SQLModel, table=True):
    """A filter-list subscription (blocklist or allowlist), scoped global /
    zone / server. Pushed to AdGuard's /control/filtering on sync."""
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    url: str
    kind: FilterKind = Field(default=FilterKind.blocklist, index=True)
    scope: ConfigScope = Field(default=ConfigScope.global_)
    zone_ids: list[int] = Field(default_factory=list, sa_type=JSON)
    server_id: Optional[int] = Field(default=None, foreign_key="server.id", index=True)
    enabled: bool = True
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow)


class BlockedService(SQLModel, table=True):
    """A service to block (e.g. "youtube", "tiktok"), scoped global / zone /
    server. The set of enabled ids is pushed to /control/blocked_services."""
    id: Optional[int] = Field(default=None, primary_key=True)
    service_id: str = Field(index=True)   # AdGuard service id, e.g. "facebook"
    scope: ConfigScope = Field(default=ConfigScope.global_)
    zone_ids: list[int] = Field(default_factory=list, sa_type=JSON)
    server_id: Optional[int] = Field(default=None, foreign_key="server.id", index=True)
    enabled: bool = True
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------- #
# Provisioning tokens (one-line server install)
# --------------------------------------------------------------------------- #
class ProvisioningToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    token: str = Field(index=True, unique=True)
    name: str                                   # name the resulting server gets
    zone_id: Optional[int] = Field(default=None, foreign_key="zone.id")
    method: InstallMethod = Field(default=InstallMethod.docker)
    prune: bool = False
    # Install the auto-updater on the box and enable auto-update on the Server.
    auto_update: bool = False

    ssl_enabled: bool = False
    # Address the admin app will use to reach the box (cert SAN). Required for SSL.
    connect_address: Optional[str] = None
    http_port: int = 3000
    https_port: int = 443
    dns_port: int = 53

    # Credentials the install script sets on the new AdGuard instance.
    admin_username: str = "admin"
    admin_password_enc: Optional[str] = None
    # Generated cert/key for the box (key encrypted at rest).
    tls_cert: Optional[str] = None
    tls_key_enc: Optional[str] = None

    status: ProvisionStatus = Field(default=ProvisionStatus.pending)
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime = Field(default_factory=utcnow)
    completed_at: Optional[datetime] = None
    server_id: Optional[int] = Field(default=None, foreign_key="server.id")

    # Secret-bearing provisioning endpoints are single-fetch: once install.sh has
    # collected the config / private key, a replay of the (log-visible) URL is
    # refused. Set to the time of the first successful fetch.
    config_fetched_at: Optional[datetime] = None
    key_fetched_at: Optional[datetime] = None
