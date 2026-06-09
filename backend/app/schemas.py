from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from .models import ConfigScope, InstallMethod, ProvisionStatus, RecordScope, Role, SyncStatus


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
    status: SyncStatus
    version: Optional[str]
    last_seen: Optional[datetime]
    last_synced: Optional[datetime]
    last_error: Optional[str]
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


class ServerUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None  # send to rotate; omit to keep existing
    zone_id: Optional[int] = None
    enabled: Optional[bool] = None
    prune: Optional[bool] = None
    manage_upstreams: Optional[bool] = None


# ---- DNS records ----
class RecordRead(BaseModel):
    id: int
    domain: str
    answer: str
    scope: RecordScope
    zone_id: Optional[int]
    enabled: bool
    description: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class RecordCreate(BaseModel):
    domain: str
    answer: str
    scope: RecordScope = RecordScope.global_
    zone_id: Optional[int] = None
    enabled: bool = True
    description: Optional[str] = None


class RecordUpdate(BaseModel):
    domain: Optional[str] = None
    answer: Optional[str] = None
    scope: Optional[RecordScope] = None
    zone_id: Optional[int] = None
    enabled: Optional[bool] = None
    description: Optional[str] = None


# ---- Upstreams ----
class UpstreamRead(BaseModel):
    id: int
    address: str
    scope: ConfigScope
    zone_id: Optional[int]
    server_id: Optional[int]
    enabled: bool
    description: Optional[str]

    class Config:
        from_attributes = True


class UpstreamCreate(BaseModel):
    address: str
    scope: ConfigScope = ConfigScope.global_
    zone_id: Optional[int] = None
    server_id: Optional[int] = None
    enabled: bool = True
    description: Optional[str] = None


class UpstreamUpdate(BaseModel):
    address: Optional[str] = None
    scope: Optional[ConfigScope] = None
    zone_id: Optional[int] = None
    server_id: Optional[int] = None
    enabled: Optional[bool] = None
    description: Optional[str] = None


# ---- Forward zones ----
class ForwardZoneRead(BaseModel):
    id: int
    domains: str
    upstreams: str
    scope: ConfigScope
    zone_id: Optional[int]
    server_id: Optional[int]
    enabled: bool
    description: Optional[str]

    class Config:
        from_attributes = True


class ForwardZoneCreate(BaseModel):
    domains: str
    upstreams: str
    scope: ConfigScope = ConfigScope.global_
    zone_id: Optional[int] = None
    server_id: Optional[int] = None
    enabled: bool = True
    description: Optional[str] = None


class ForwardZoneUpdate(BaseModel):
    domains: Optional[str] = None
    upstreams: Optional[str] = None
    scope: Optional[ConfigScope] = None
    zone_id: Optional[int] = None
    server_id: Optional[int] = None
    enabled: Optional[bool] = None
    description: Optional[str] = None


# ---- Provisioning ----
class ProvisionRequest(BaseModel):
    name: str
    zone_id: Optional[int] = None
    method: InstallMethod = InstallMethod.docker
    ssl_enabled: bool = False
    connect_address: Optional[str] = None  # FQDN/IP; required when ssl_enabled
    http_port: Optional[int] = None
    https_port: Optional[int] = None
    prune: bool = False


class ProvisionTokenRead(BaseModel):
    id: int
    name: str
    zone_id: Optional[int]
    method: InstallMethod
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
    address: Optional[str] = None
    http_port: Optional[int] = None
    https_port: Optional[int] = None


# ---- Sync ----
class SyncResultRead(BaseModel):
    server_id: int
    server_name: str
    status: SyncStatus
    added: list[str]
    deleted: list[str]
    upstreams_changed: bool = False
    error: Optional[str]
    version: Optional[str]
