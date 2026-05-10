"""
CMDB entity resolver. Provides O(1) lookups for users and devices via indexes
built at construction time. All log generation must route through here —
never read CMDB lists directly when resolving entities for log rows.
"""
from cmdb.schema import CMDB, CMDBUser, CMDBDevice
from typing import Optional


class CMDBResolver:
    def __init__(self, cmdb: CMDB):
        self.cmdb = cmdb
        # Build indexes at construction time — O(1) lookups during generation
        self._user_by_username = {u.username: u for u in cmdb.users}
        self._user_by_email = {u.email: u for u in cmdb.users}
        self._user_by_upn = {u.upn: u for u in cmdb.users}
        self._device_by_hostname = {d.hostname: d for d in cmdb.devices}
        self._device_by_ip = {d.ip_address: d for d in cmdb.devices}
        self._server_by_hostname = {s.hostname: s for s in cmdb.servers}

    def resolve_user(self, identifier: str) -> Optional[CMDBUser]:
        """Resolve user by username, email, or UPN."""
        return (
            self._user_by_username.get(identifier)
            or self._user_by_email.get(identifier)
            or self._user_by_upn.get(identifier)
        )

    def resolve_device(self, identifier: str) -> Optional[CMDBDevice]:
        """Resolve device by hostname or IP address."""
        return (
            self._device_by_hostname.get(identifier)
            or self._device_by_ip.get(identifier)
            or self._server_by_hostname.get(identifier)
        )

    def get_user_context(self, username: str) -> dict:
        """
        Returns the full grounding context for a user.
        This is the canonical source for all user-related field values
        in generated log rows — never use values from anywhere else.
        """
        user = self.resolve_user(username)
        if not user:
            return {"error": f"User '{username}' not found in CMDB"}
        device = self.resolve_device(user.workstation) if user.workstation else None
        return {
            "username": user.username,
            "email": user.email,
            "upn": user.upn,
            "display_name": user.display_name,
            "department": user.department,
            "account_name": user.username,
            "account_domain": self.cmdb.network.netbios_domain,
            "account_upn": user.upn,
            "device_name": device.hostname if device else None,
            "device_id": device.device_id if device else None,
            "device_fqdn": device.fqdn if device else None,
            "ip_address": user.normal_source_ips[0] if user.normal_source_ips else None,
            "normal_login_hours": user.normal_login_hours,
            "normal_login_days": user.normal_login_days,
            "is_vip": user.is_vip,
            "mfa_enrolled": user.mfa_enrolled,
        }
