"""Tests for agent tool functions — resolver integration and row limit enforcement."""
from unittest.mock import MagicMock


def make_mock_agent(users=None, devices=None, schema=None):
    from cmdb.schema import CMDB, CMDBUser, CMDBDevice, CMDBNetwork, CMDBInfrastructure
    from cmdb.resolver import CMDBResolver
    cmdb = CMDB(
        organization="Test",
        users=users or [],
        devices=devices or [],
        network=CMDBNetwork(
            domain="corp.com",
            netbios_domain="CORP",
            internal_subnets=["10.0.0.0/8"],
            domain_controllers=["DC01"],
            dns_servers=["10.0.0.1"],
        ),
        infrastructure=CMDBInfrastructure(
            email_security=["MDO"],
            endpoint_security="MDE",
        ),
    )
    agent = MagicMock()
    agent.cmdb = cmdb
    agent.resolver = CMDBResolver(cmdb)
    agent.fp_schema = schema or {}
    agent.generated_tables = {}
    agent.gaps = []
    return agent


def test_resolve_user_returns_device_id():
    from cmdb.schema import CMDBUser, CMDBDevice
    from agent.tools import _tool_resolve_user
    user = CMDBUser(
        username="jsmith",
        email="jsmith@corp.com",
        upn="jsmith@corp.onmicrosoft.com",
        display_name="John Smith",
        department="Finance",
        title="Analyst",
        workstation="CORP-WS-042",
        normal_source_ips=["10.1.4.52"],
    )
    device = CMDBDevice(
        hostname="CORP-WS-042",
        device_id="dev-001",
        fqdn="CORP-WS-042.corp.com",
        os="Windows 11",
        os_version="23H2",
        os_build="22631",
        ip_address="10.1.4.52",
        mac_address="00:11:22:33:44:55",
        subnet="10.1.4.0/24",
    )
    agent = make_mock_agent(users=[user], devices=[device])
    result = _tool_resolve_user({"identifier": "jsmith"}, agent)
    assert result["username"] == "jsmith"
    assert result["device_id"] == "dev-001"
    assert result["normal_ip"] == "10.1.4.52"


def test_resolve_unknown_user_returns_error():
    from agent.tools import _tool_resolve_user
    agent = make_mock_agent()
    result = _tool_resolve_user({"identifier": "nobody"}, agent)
    assert "error" in result


def test_add_log_rows_separates_bau_malicious():
    from agent.tools import _tool_add_log_rows
    agent = make_mock_agent(
        schema={"DeviceProcessEvents": {"columns": [], "action_types": []}}
    )
    _tool_add_log_rows(
        {
            "table_name": "DeviceProcessEvents",
            "rows": [{"ActionType": "ProcessCreated"}],
            "row_type": "bau",
        },
        agent,
    )
    _tool_add_log_rows(
        {
            "table_name": "DeviceProcessEvents",
            "rows": [{"ActionType": "ProcessInjected"}],
            "row_type": "malicious",
        },
        agent,
    )
    assert len(agent.generated_tables["DeviceProcessEvents"]["bau"]) == 1
    assert len(agent.generated_tables["DeviceProcessEvents"]["malicious"]) == 1


def test_add_log_rows_enforces_per_call_limit():
    from agent.tools import _tool_add_log_rows
    agent = make_mock_agent(
        schema={"DeviceProcessEvents": {"columns": [], "action_types": []}}
    )
    big_batch = [{"ActionType": "ProcessCreated"}] * 10_001
    result = _tool_add_log_rows(
        {
            "table_name": "DeviceProcessEvents",
            "rows": big_batch,
            "row_type": "bau",
        },
        agent,
    )
    assert "error" in result


def test_report_gap_recorded():
    from agent.tools import _tool_report_gap
    agent = make_mock_agent()
    agent.gaps = []
    result = _tool_report_gap(
        {
            "scenario_step": "Attacker sends Teams message",
            "mitre_technique": "T1534",
            "missing_table": "TeamsMessageEvents",
            "missing_source": "Microsoft Purview",
            "suggested_tools": ["Microsoft Purview", "Defender XDR"],
            "impact": "Teams lateral phishing is invisible",
        },
        agent,
    )
    assert result["gap_recorded"] is True
    assert len(agent.gaps) == 1
    assert agent.gaps[0]["missing_table"] == "TeamsMessageEvents"
