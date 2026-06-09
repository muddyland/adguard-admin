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
    # Pinned PEM certificate for verifying TLS to this server (self-signed boxes).
    tls_cert: Optional[str] = None

    # Health / sync bookkeeping (updated by the reconcile loop)
    status: SyncStatus = Field(default=SyncStatus.unknown)
    version: Optional[str] = None
    last_seen: Optional[datetime] = None
    last_synced: Optional[datetime] = None
    last_error: Optional[str] = None
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
# Provisioning tokens (one-line server install)
# --------------------------------------------------------------------------- #
class ProvisioningToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    token: str = Field(index=True, unique=True)
    name: str                                   # name the resulting server gets
    zone_id: Optional[int] = Field(default=None, foreign_key="zone.id")
    method: InstallMethod = Field(default=InstallMethod.docker)
    prune: bool = False

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
