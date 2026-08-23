from datetime import datetime
from typing import Optional

from pydantic import BaseModel, field_validator

from .validators import (
    validate_display_name,
    validate_host,
    validate_port,
    validate_server_url,
)
from .models import (
    ConfigScope,
    DnsServerKind,
    FilterKind,
    InstallMethod,
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

    class Config:
        from_attributes = True


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
    created_at: datetime
    server_count: int = 0
    record_count: int = 0

    class Config:
        from_attributes = True


class ZoneCreate(BaseModel):
    name: str
    slug: Optional[str] = None
    description: Optional[str] = None


class ZoneUpdate(BaseModel):
    name: Optional[str] = None
    slug: Optional[str] = None
    description: Optional[str] = None


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
    created_at: datetime

    class Config:
        from_attributes = True


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

    class Config:
        from_attributes = True


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

    class Config:
        from_attributes = True


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

    class Config:
        from_attributes = True


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

    class Config:
        from_attributes = True


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

    class Config:
        from_attributes = True


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
    method: InstallMethod = InstallMethod.docker
    ssl_enabled: bool = False
    connect_address: Optional[str] = None  # FQDN/IP; required when ssl_enabled
    http_port: Optional[int] = None
    https_port: Optional[int] = None
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

    @field_validator("http_port", "https_port")
    @classmethod
    def _check_ports(cls, v: Optional[int]) -> Optional[int]:
        if v is None:
            return None
        return validate_port(v, field="port")


class ProvisionTokenRead(BaseModel):
    id: int
    name: str
    zone_id: Optional[int]
    method: InstallMethod
    auto_update: bool
    ssl_enabled: bool
    connect_address: Optional[str]
    http_port: int
    https_port: int
    status: ProvisionStatus
    token: str
    command: str
    created_at: datetime
    expires_at: datetime
    completed_at: Optional[datetime]
    server_id: Optional[int]


class ProvisionComplete(BaseModel):
    """Posted by install.sh on the target box. Token-authenticated only, so the
    address it reports becomes a URL this app connects to with credentials and
    reverse-proxies — it must be a plain host, never an arbitrary URL."""

    address: Optional[str] = None
    http_port: Optional[int] = None
    https_port: Optional[int] = None

    @field_validator("address")
    @classmethod
    def _check_address(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v.strip() == "":
            return None
        return validate_host(v, field="address")

    @field_validator("http_port", "https_port")
    @classmethod
    def _check_ports(cls, v: Optional[int]) -> Optional[int]:
        if v is None:
            return None
        return validate_port(v, field="port")


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
    # Why this server would be skipped right now (None = it is due).
    skip_reason: Optional[str] = None

    class Config:
        from_attributes = True


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
