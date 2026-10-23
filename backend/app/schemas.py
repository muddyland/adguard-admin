from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, field_validator

from .validators import (
    validate_cidr,
    validate_display_name,
    validate_host,
    validate_image_ref,
    validate_interface,
    validate_listen_address,
    validate_port,
    validate_priority,
    validate_router_id,
    validate_server_url,
    validate_vip,
)
from .models import (
    AgentRole,
    ConfigScope,
    DnsServerKind,
    FilterKind,
    HealthCheckMode,
    InstallMethod,
    IpvsAlgo,
    LbMode,
    LbPolicy,
    ProvisionStatus,
    RecordScope,
    Role,
    SyncStatus,
    UpdateState,
)


# ---- Auth ----
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    username: str
    password: str


# ---- Users ----
class UserRead(BaseModel):
    id: int
    username: str
    email: Optional[str]
    role: Role
    is_active: bool
    oidc_sub: Optional[str]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserCreate(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    role: Role = Role.viewer


class UserUpdate(BaseModel):
    email: Optional[str] = None
    role: Optional[Role] = None
    is_active: Optional[bool] = None
    password: Optional[str] = None


# ---- Zones ----
class ZoneRead(BaseModel):
    id: int
    name: str
    slug: str
    description: Optional[str]
    vip: Optional[str] = None
    vrrp_router_id: Optional[int] = None
    created_at: datetime
    server_count: int = 0
    record_count: int = 0
    load_balancer_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class ZoneCreate(BaseModel):
    name: str
    slug: Optional[str] = None
    description: Optional[str] = None
    vip: Optional[str] = None
    vrrp_router_id: Optional[int] = None

    @field_validator("vip")
    @classmethod
    def _check_vip(cls, v: Optional[str]) -> Optional[str]:
        return validate_vip(v)

    @field_validator("vrrp_router_id")
    @classmethod
    def _check_router_id(cls, v: Optional[int]) -> Optional[int]:
        return validate_router_id(v)


class ZoneUpdate(BaseModel):
    name: Optional[str] = None
    slug: Optional[str] = None
    description: Optional[str] = None
    vip: Optional[str] = None
    vrrp_router_id: Optional[int] = None

    @field_validator("vip")
    @classmethod
    def _check_vip(cls, v: Optional[str]) -> Optional[str]:
        return validate_vip(v)

    @field_validator("vrrp_router_id")
    @classmethod
    def _check_router_id(cls, v: Optional[int]) -> Optional[int]:
        return validate_router_id(v)


# ---- Servers ----
class ServerRead(BaseModel):
    id: int
    name: str
    url: str
    username: Optional[str]
    zone_id: Optional[int]
    enabled: bool
    prune: bool
    manage_upstreams: bool
    manage_filtering: bool
    auto_update: bool
    install_method: Optional[InstallMethod]
    can_autoupdate: bool
    update_check_disabled: bool
    update_state: UpdateState
    update_attempted_at: Optional[datetime]
    update_completed_at: Optional[datetime]
    update_error: Optional[str]
    status: SyncStatus
    version: Optional[str]
    latest_version: Optional[str]
    update_available: bool
    last_seen: Optional[datetime]
    last_synced: Optional[datetime]
    last_error: Optional[str]
    cooldown_until: Optional[datetime]
    in_sync: bool
    agent_id: Optional[int] = None
    dns_port: int = 53
    expose_web_ui: bool = False
    agent_state: Optional[dict] = None
    lb_state: Optional[dict] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ServerCreate(BaseModel):
    name: str
    url: str
    username: Optional[str] = None
    password: Optional[str] = None
    zone_id: Optional[int] = None
    enabled: bool = True
    prune: bool = False
    manage_upstreams: bool = False
    manage_filtering: bool = False
    # None means "use AUTO_UPDATE_DEFAULT".
    auto_update: Optional[bool] = None
    install_method: Optional[InstallMethod] = None
    dns_port: int = 53
    expose_web_ui: bool = False

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: str) -> str:
        return validate_display_name(v, field="name")

    @field_validator("url")
    @classmethod
    def _check_url(cls, v: str) -> str:
        return validate_server_url(v)


class ServerUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None  # send to rotate; omit to keep existing
    zone_id: Optional[int] = None
    enabled: Optional[bool] = None
    prune: Optional[bool] = None
    manage_upstreams: Optional[bool] = None
    manage_filtering: Optional[bool] = None
    auto_update: Optional[bool] = None
    install_method: Optional[InstallMethod] = None
    dns_port: Optional[int] = None
    expose_web_ui: Optional[bool] = None

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return validate_display_name(v, field="name")

    @field_validator("url")
    @classmethod
    def _check_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return validate_server_url(v)


# ---- DNS records ----
class RecordRead(BaseModel):
    id: int
    domain: str
    answer: str
    scope: RecordScope
    zone_ids: list[int]
    enabled: bool
    description: Optional[str]
    managed: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RecordCreate(BaseModel):
    domain: str
    answer: str
    scope: RecordScope = RecordScope.global_
    zone_ids: list[int] = []
    enabled: bool = True
    description: Optional[str] = None


class RecordUpdate(BaseModel):
    domain: Optional[str] = None
    answer: Optional[str] = None
    scope: Optional[RecordScope] = None
    zone_ids: Optional[list[int]] = None
    enabled: Optional[bool] = None
    description: Optional[str] = None


# ---- Upstreams ----
class UpstreamRead(BaseModel):
    id: int
    address: str
    kind: DnsServerKind
    scope: ConfigScope
    zone_ids: list[int]
    server_id: Optional[int]
    enabled: bool
    description: Optional[str]

    model_config = ConfigDict(from_attributes=True)


class UpstreamCreate(BaseModel):
    address: str
    kind: DnsServerKind = DnsServerKind.upstream
    scope: ConfigScope = ConfigScope.global_
    zone_ids: list[int] = []
    server_id: Optional[int] = None
    enabled: bool = True
    description: Optional[str] = None


class UpstreamUpdate(BaseModel):
    address: Optional[str] = None
    kind: Optional[DnsServerKind] = None
    scope: Optional[ConfigScope] = None
    zone_ids: Optional[list[int]] = None
    server_id: Optional[int] = None
    enabled: Optional[bool] = None
    description: Optional[str] = None


# ---- Forward zones ----
class ForwardZoneRead(BaseModel):
    id: int
    domains: str
    upstreams: str
    scope: ConfigScope
    zone_ids: list[int]
    server_id: Optional[int]
    enabled: bool
    description: Optional[str]

    model_config = ConfigDict(from_attributes=True)


class ForwardZoneCreate(BaseModel):
    domains: str
    upstreams: str
    scope: ConfigScope = ConfigScope.global_
    zone_ids: list[int] = []
    server_id: Optional[int] = None
    enabled: bool = True
    description: Optional[str] = None


class ForwardZoneUpdate(BaseModel):
    domains: Optional[str] = None
    upstreams: Optional[str] = None
    scope: Optional[ConfigScope] = None
    zone_ids: Optional[list[int]] = None
    server_id: Optional[int] = None
    enabled: Optional[bool] = None
    description: Optional[str] = None


# ---- Filter lists (blocklists / allowlists) ----
class FilterListRead(BaseModel):
    id: int
    name: str
    url: str
    kind: FilterKind
    scope: ConfigScope
    zone_ids: list[int]
    server_id: Optional[int]
    enabled: bool
    description: Optional[str]

    model_config = ConfigDict(from_attributes=True)


class FilterListCreate(BaseModel):
    name: str
    url: str
    kind: FilterKind = FilterKind.blocklist
    scope: ConfigScope = ConfigScope.global_
    zone_ids: list[int] = []
    server_id: Optional[int] = None
    enabled: bool = True
    description: Optional[str] = None


class FilterListUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    kind: Optional[FilterKind] = None
    scope: Optional[ConfigScope] = None
    zone_ids: Optional[list[int]] = None
    server_id: Optional[int] = None
    enabled: Optional[bool] = None
    description: Optional[str] = None


# ---- Blocked services ----
class BlockedServiceRead(BaseModel):
    id: int
    service_id: str
    scope: ConfigScope
    zone_ids: list[int]
    server_id: Optional[int]
    enabled: bool
    description: Optional[str]

    model_config = ConfigDict(from_attributes=True)


class BlockedServiceCreate(BaseModel):
    service_id: str
    scope: ConfigScope = ConfigScope.global_
    zone_ids: list[int] = []
    server_id: Optional[int] = None
    enabled: bool = True
    description: Optional[str] = None


class BlockedServiceUpdate(BaseModel):
    service_id: Optional[str] = None
    scope: Optional[ConfigScope] = None
    zone_ids: Optional[list[int]] = None
    server_id: Optional[int] = None
    enabled: Optional[bool] = None
    description: Optional[str] = None


# ---- Catalog (curated popular lists / services) ----
class CatalogFilter(BaseModel):
    name: str
    url: str
    kind: FilterKind
    description: Optional[str] = None
    recommended: bool = False


class CatalogService(BaseModel):
    service_id: str
    name: str
    recommended: bool = False


# ---- Provisioning ----
# These fields are interpolated into a bash script that runs as root on the
# target host and into the URL the reconcile loop later connects to, so they are
# validated here rather than only quoted at render time.
class ProvisionRequest(BaseModel):
    name: str
    zone_id: Optional[int] = None
    # Roles the host will run. The install script installs the agent only; the
    # roles are converged by reconciliation once the agent has enrolled.
    roles: list[AgentRole] = [AgentRole.adguard]
    # How the AdGuard role is installed on the box (ignored without that role).
    method: InstallMethod = InstallMethod.docker
    # Address this app will reach the agent at (cert SAN). Defaults to the
    # address the agent reports at enrollment.
    connect_address: Optional[str] = None
    agent_port: Optional[int] = None
    expose_web_ui: bool = False
    vrrp_priority: int = 100
    lb_mode: LbMode = LbMode.dnsdist
    prune: bool = False
    # Keep AdGuard Home up to date on the new box. For a Docker install the
    # script also installs the on-box updater; a bare-metal box is upgraded by
    # this app over the control API. None means "use AUTO_UPDATE_DEFAULT".
    auto_update: Optional[bool] = None

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: str) -> str:
        return validate_display_name(v, field="name")

    @field_validator("connect_address")
    @classmethod
    def _check_address(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v.strip() == "":
            return None
        return validate_host(v, field="connect_address")

    @field_validator("agent_port")
    @classmethod
    def _check_ports(cls, v: Optional[int]) -> Optional[int]:
        if v is None:
            return None
        return validate_port(v, field="agent_port")

    @field_validator("roles")
    @classmethod
    def _check_roles(cls, v: list[AgentRole]) -> list[AgentRole]:
        if not v:
            raise ValueError("at least one role is required")
        return list(dict.fromkeys(v))

    @field_validator("vrrp_priority")
    @classmethod
    def _check_priority(cls, v: int) -> int:
        return validate_priority(v)


class ProvisionTokenRead(BaseModel):
    id: int
    name: str
    zone_id: Optional[int]
    roles: list[str]
    method: InstallMethod
    auto_update: bool
    connect_address: Optional[str]
    agent_port: int
    vrrp_priority: int
    expose_web_ui: bool
    lb_mode: LbMode = LbMode.dnsdist
    status: ProvisionStatus
    token: str
    command: str
    created_at: datetime
    expires_at: datetime
    completed_at: Optional[datetime]
    server_id: Optional[int]
    agent_id: Optional[int] = None
    load_balancer_id: Optional[int] = None


class EnrollRequest(BaseModel):
    """Posted by `adguard-admin-agent enroll` on the target box. Token-authenticated
    only, so the address it reports becomes a URL this app connects to over mTLS
    and must be a plain host, never an arbitrary URL."""

    csr_pem: str
    hostname: Optional[str] = None
    address: Optional[str] = None
    port: Optional[int] = None
    os: Optional[str] = None
    arch: Optional[str] = None
    agent_version: Optional[str] = None

    @field_validator("address")
    @classmethod
    def _check_address(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v.strip() == "":
            return None
        return validate_host(v, field="address")

    @field_validator("port")
    @classmethod
    def _check_port(cls, v: Optional[int]) -> Optional[int]:
        return None if v is None else validate_port(v, field="port")

    @field_validator("hostname", "os", "arch", "agent_version")
    @classmethod
    def _check_short(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()[:100]
        if any(ord(c) < 32 or ord(c) == 127 for c in v):
            raise ValueError("must not contain control characters")
        return v or None

    @field_validator("csr_pem")
    @classmethod
    def _check_csr(cls, v: str) -> str:
        v = (v or "").strip()
        if "BEGIN CERTIFICATE REQUEST" not in v or len(v) > 16384:
            raise ValueError("csr_pem must be a PEM certificate request")
        return v


class EnrollResponse(BaseModel):
    agent_id: int
    name: str
    cert_pem: str
    ca_pem: str
    not_after: datetime


# ---- Automatic updates ----
class UpdateServerRead(BaseModel):
    """One server's update posture, as shown on the Updates page."""
    id: int
    name: str
    zone_id: Optional[int]
    enabled: bool
    status: SyncStatus
    version: Optional[str]
    latest_version: Optional[str]
    update_available: bool
    auto_update: bool
    install_method: Optional[InstallMethod]
    can_autoupdate: bool
    update_check_disabled: bool
    update_state: UpdateState
    update_attempted_at: Optional[datetime]
    update_completed_at: Optional[datetime]
    update_error: Optional[str]
    agent_id: Optional[int] = None
    # Why this server would be skipped right now (None = it is due).
    skip_reason: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class UpdateOverviewRead(BaseModel):
    servers: list[UpdateServerRead]
    enabled: bool                 # AUTO_UPDATE_ENABLED
    window: str                   # "" = any time
    in_window: bool
    interval_seconds: int
    retry_hours: int
    last_run: Optional[datetime]
    pass_in_progress: bool
    docker_agent_command: str     # the one-liner for dockerised servers


class UpdateOutcomeRead(BaseModel):
    server_id: int
    server_name: str
    state: UpdateState
    from_version: Optional[str]
    to_version: Optional[str]
    message: str


# ---- Sync ----
class SyncResultRead(BaseModel):
    server_id: int
    server_name: str
    status: SyncStatus
    added: list[str]
    deleted: list[str]
    upstreams_changed: bool = False
    filtering_changed: bool = False
    error: Optional[str]
    version: Optional[str]



# ---- Agents ----
class AgentRead(BaseModel):
    id: int
    name: str
    url: str
    zone_id: Optional[int]
    address: str
    port: int
    hostname: Optional[str]
    os: Optional[str]
    arch: Optional[str]
    version: Optional[str]
    status: SyncStatus
    last_seen: Optional[datetime]
    last_error: Optional[str]
    cert_not_after: Optional[datetime]
    roles: list[str] = []
    health: Optional[dict] = None
    info: Optional[dict] = None
    server_ids: list[int] = []
    load_balancer_ids: list[int] = []
    update_available: bool = False
    update_attempted_at: Optional[datetime] = None
    update_error: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AgentUpdate(BaseModel):
    name: Optional[str] = None
    zone_id: Optional[int] = None

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: Optional[str]) -> Optional[str]:
        return None if v is None else validate_display_name(v, field="name")


class AgentServiceResult(BaseModel):
    ok: bool
    message: str = ""


class AgentLogs(BaseModel):
    lines: list[str]


# ---- Load balancers ----
class LbBackendLive(BaseModel):
    state: Optional[str] = None
    drained: bool = False
    qps: Optional[float] = None
    queries: Optional[float] = None
    latency_ms: Optional[float] = None
    outstanding: Optional[float] = None
    drop_rate: Optional[float] = None
    # ipvs mode only
    conns: Optional[float] = None
    active_conns: Optional[float] = None
    inactive_conns: Optional[float] = None


class LbBackendRead(BaseModel):
    server_id: int
    server_name: str
    address: str
    port: int
    enabled: bool
    weight: int
    order: int
    live: Optional[LbBackendLive] = None


class LoadBalancerRead(BaseModel):
    id: int
    name: str
    zone_id: Optional[int]
    agent_id: int
    enabled: bool
    install_method: InstallMethod
    image: str
    listen_addresses: list[str]
    policy: LbPolicy
    ecs: bool
    cache_enabled: bool
    cache_max_entries: int
    hc_name: str
    hc_interval_s: int
    hc_max_failures: int
    hc_rise: int
    hc_mode: HealthCheckMode
    acl: list[str]
    vrrp_priority: int
    vip_interface: str
    mode: LbMode = LbMode.dnsdist
    ipvs_algo: IpvsAlgo = IpvsAlgo.wlc
    vip: Optional[str] = None
    status: SyncStatus
    in_sync: bool
    last_synced: Optional[datetime]
    last_error: Optional[str]
    desired_hash: Optional[str]
    applied_hash: Optional[str]
    state: Optional[dict] = None
    keepalived_state: Optional[dict] = None
    backends: list[LbBackendRead] = []
    created_at: datetime


class _LbFields(BaseModel):
    install_method: Optional[InstallMethod] = None
    image: Optional[str] = None
    listen_addresses: Optional[list[str]] = None
    policy: Optional[LbPolicy] = None
    ecs: Optional[bool] = None
    cache_enabled: Optional[bool] = None
    cache_max_entries: Optional[int] = None
    hc_name: Optional[str] = None
    hc_interval_s: Optional[int] = None
    hc_max_failures: Optional[int] = None
    hc_rise: Optional[int] = None
    hc_mode: Optional[HealthCheckMode] = None
    acl: Optional[list[str]] = None
    vrrp_priority: Optional[int] = None
    vip_interface: Optional[str] = None
    mode: Optional[LbMode] = None
    ipvs_algo: Optional[IpvsAlgo] = None

    @field_validator("image")
    @classmethod
    def _check_image(cls, v: Optional[str]) -> Optional[str]:
        return None if v is None else validate_image_ref(v)

    @field_validator("listen_addresses")
    @classmethod
    def _check_listen(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        if v is None:
            return None
        out = [validate_listen_address(a) for a in v if a and a.strip()]
        if not out:
            raise ValueError("at least one listen address is required")
        return out

    @field_validator("acl")
    @classmethod
    def _check_acl(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        if v is None:
            return None
        return [validate_cidr(a) for a in v if a and a.strip()]

    @field_validator("hc_name")
    @classmethod
    def _check_hc_name(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        if not v.endswith("."):
            v += "."
        validate_host(v.rstrip("."), field="hc_name")
        return v

    @field_validator("cache_max_entries", "hc_interval_s", "hc_max_failures", "hc_rise")
    @classmethod
    def _check_positive(cls, v: Optional[int]) -> Optional[int]:
        if v is None:
            return None
        if not (1 <= v <= 100_000_000):
            raise ValueError("must be a positive integer")
        return v

    @field_validator("vrrp_priority")
    @classmethod
    def _check_priority(cls, v: Optional[int]) -> Optional[int]:
        return None if v is None else validate_priority(v)

    @field_validator("vip_interface")
    @classmethod
    def _check_iface(cls, v: Optional[str]) -> Optional[str]:
        return None if v is None else validate_interface(v)


class LoadBalancerCreate(_LbFields):
    name: str
    zone_id: Optional[int] = None
    agent_id: int
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: str) -> str:
        return validate_display_name(v, field="name")


class LoadBalancerUpdate(_LbFields):
    name: Optional[str] = None
    zone_id: Optional[int] = None
    agent_id: Optional[int] = None
    enabled: Optional[bool] = None

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: Optional[str]) -> Optional[str]:
        return None if v is None else validate_display_name(v, field="name")


class LbBackendUpdate(BaseModel):
    enabled: Optional[bool] = None
    weight: Optional[int] = None
    order: Optional[int] = None

    @field_validator("weight", "order")
    @classmethod
    def _check_positive(cls, v: Optional[int]) -> Optional[int]:
        if v is None:
            return None
        if not (1 <= v <= 2_147_483_647):
            raise ValueError("must be a positive integer")
        return v


class LoadBalancerState(BaseModel):
    dnsdist: Optional[dict] = None
    keepalived: Optional[dict] = None
