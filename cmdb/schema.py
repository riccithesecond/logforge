"""
CMDB data models. All entity field values used in log generation must come
from these models — never invent usernames, device IDs, or IP addresses.
"""
from pydantic import BaseModel, field_validator
from typing import Optional
import ipaddress


class CMDBUser(BaseModel):
    username: str
    email: str
    upn: str
    display_name: str
    department: str
    title: str
    is_vip: bool = False
    manager: Optional[str] = None
    workstation: Optional[str] = None
    normal_login_hours: str = "08:00-18:00"
    normal_login_days: list[str] = ["Mon", "Tue", "Wed", "Thu", "Fri"]
    normal_source_ips: list[str] = []
    mfa_enrolled: bool = True
    cloud_accounts: list[str] = []
    proofpoint_vip: bool = False
    abnormal_vip: bool = False

    @field_validator("email", "upn")
    @classmethod
    def must_contain_at(cls, v: str) -> str:
        if "@" not in v:
            raise ValueError(f"Not a valid email/UPN: {v}")
        return v


class CMDBDevice(BaseModel):
    hostname: str
    device_id: str
    fqdn: str
    os: str
    os_version: str
    os_build: str
    primary_user: Optional[str] = None
    department: Optional[str] = None
    ip_address: str
    mac_address: str
    subnet: str
    managed: bool = True
    av_product: str = "Microsoft Defender"
    sensor_version: Optional[str] = None
    asset_type: str = "workstation"

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v

    @field_validator("subnet")
    @classmethod
    def validate_subnet(cls, v: str) -> str:
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError(f"Invalid subnet: {v}")
        return v


class CMDBServer(BaseModel):
    hostname: str
    device_id: str
    fqdn: str
    os: str
    os_version: str
    ip_address: str
    subnet: str
    role: str
    managed: bool = True
    criticality: str = "medium"


class CMDBNetwork(BaseModel):
    domain: str
    netbios_domain: str
    internal_subnets: list[str]
    dmz_subnets: list[str] = []
    domain_controllers: list[str]
    dns_servers: list[str]
    proxy_address: Optional[str] = None
    email_gateway: Optional[str] = None
    vpn_gateway: Optional[str] = None
    public_egress_ips: list[str] = []


class CMDBInfrastructure(BaseModel):
    email_security: list[str]
    endpoint_security: str
    proxy: Optional[str] = None
    cloud_providers: list[str] = []
    identity_provider: str = "Entra ID"
    siem: str = "fried-plantains"
    registered_tables: list[str] = []


class CMDB(BaseModel):
    organization: str
    users: list[CMDBUser]
    devices: list[CMDBDevice]
    servers: list[CMDBServer] = []
    network: CMDBNetwork
    infrastructure: CMDBInfrastructure

    def get_user(self, username: str) -> Optional[CMDBUser]:
        return next((u for u in self.users if u.username == username), None)

    def get_device(self, hostname: str) -> Optional[CMDBDevice]:
        return next((d for d in self.devices if d.hostname == hostname), None)

    def get_user_device(self, username: str) -> Optional[CMDBDevice]:
        user = self.get_user(username)
        if user and user.workstation:
            return self.get_device(user.workstation)
        return None

    def is_internal_ip(self, ip: str) -> bool:
        import ipaddress as _ip
        for subnet in self.network.internal_subnets:
            try:
                if _ip.ip_address(ip) in _ip.ip_network(subnet, strict=False):
                    return True
            except ValueError:
                pass
        return False
