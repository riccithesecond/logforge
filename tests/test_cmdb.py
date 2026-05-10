"""Tests for CMDB loading, cross-reference validation, and entity resolution."""
import json
import pytest


def test_cmdb_loads_and_all_users_resolve():
    from cmdb.loader import load_cmdb
    from cmdb.resolver import CMDBResolver
    cmdb = load_cmdb("cmdb/environment.json")
    resolver = CMDBResolver(cmdb)
    for user in cmdb.users:
        resolved = resolver.resolve_user(user.username)
        assert resolved is not None
        resolved_by_email = resolver.resolve_user(user.email)
        assert resolved_by_email is not None


def test_user_workstation_cross_reference():
    from cmdb.loader import load_cmdb
    from cmdb.resolver import CMDBResolver
    cmdb = load_cmdb("cmdb/environment.json")
    resolver = CMDBResolver(cmdb)
    for user in cmdb.users:
        if user.workstation:
            device = resolver.resolve_device(user.workstation)
            assert device is not None, (
                f"User '{user.username}' workstation '{user.workstation}' missing from devices"
            )


def test_user_context_returns_device_id():
    from cmdb.loader import load_cmdb
    from cmdb.resolver import CMDBResolver
    cmdb = load_cmdb("cmdb/environment.json")
    resolver = CMDBResolver(cmdb)
    for user in cmdb.users:
        if user.workstation:
            ctx = resolver.get_user_context(user.username)
            assert ctx["device_id"] is not None
            assert ctx["device_name"] == user.workstation


def test_invalid_cmdb_workstation_raises(tmp_path):
    from cmdb.loader import load_cmdb
    bad_cmdb = {
        "organization": "test",
        "users": [{
            "username": "jsmith",
            "email": "jsmith@corp.com",
            "upn": "jsmith@corp.onmicrosoft.com",
            "display_name": "John Smith",
            "department": "IT",
            "title": "Analyst",
            "workstation": "NONEXISTENT-WS",
        }],
        "devices": [],
        "network": {
            "domain": "corp.com",
            "netbios_domain": "CORP",
            "internal_subnets": ["10.0.0.0/8"],
            "domain_controllers": ["DC01"],
            "dns_servers": ["10.0.0.1"],
        },
        "infrastructure": {
            "email_security": ["MDO"],
            "endpoint_security": "MDE",
        },
    }
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(bad_cmdb))
    with pytest.raises(ValueError, match="NONEXISTENT-WS"):
        load_cmdb(str(p))
