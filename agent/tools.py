"""
Tool function implementations for the logforge agent loop.
All functions follow the same contract:
  - Accept (inp: dict, agent) as arguments
  - Return a dict on both success and failure
  - On failure: return {"error": "message"} — never raise exceptions
  - Exceptions from tool functions crash the agent loop, so errors are caught here
"""
import logging
from schema.validator import validate_rows as _validate_rows

logger = logging.getLogger(__name__)

# Tool schema definitions passed to the Claude API
TOOL_DEFINITIONS = [
    {
        "name": "get_table_schema",
        "description": (
            "Retrieve the schema for a fried-plantains table, including column names, "
            "types, nullability, and valid ActionType values. Call this before generating "
            "any rows for a table. Column names are case-sensitive."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "table_name": {
                    "type": "string",
                    "description": "The exact fried-plantains table name, e.g. DeviceProcessEvents",
                }
            },
            "required": ["table_name"],
        },
    },
    {
        "name": "resolve_user",
        "description": (
            "Look up a user in the CMDB by username, email address, or UPN. "
            "Returns the user's canonical field values including DeviceName, DeviceId, "
            "AccountName, AccountDomain, and primary IP. Always call this before generating "
            "any log row that involves an internal user."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "identifier": {
                    "type": "string",
                    "description": "Username, email address, or UPN to look up",
                }
            },
            "required": ["identifier"],
        },
    },
    {
        "name": "resolve_device",
        "description": (
            "Look up a device in the CMDB by hostname or IP address. "
            "Returns the device's canonical field values. Call this before generating "
            "rows involving a device that is not the user's primary workstation."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "identifier": {
                    "type": "string",
                    "description": "Hostname or IP address to look up",
                }
            },
            "required": ["identifier"],
        },
    },
    {
        "name": "add_log_rows",
        "description": (
            "Add generated log rows to a table. Rows must use exact column names from "
            "get_table_schema(). Field values for users and devices must come from "
            "resolve_user() or resolve_device() — never invent them. "
            "Max 10,000 rows per call. Max 50,000 rows per table across all calls."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "table_name": {
                    "type": "string",
                    "description": "Target table name",
                },
                "rows": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "List of row dicts with exact column names",
                },
                "row_type": {
                    "type": "string",
                    "enum": ["bau", "malicious"],
                    "description": "Whether these are benign BAU rows or malicious attack rows",
                },
            },
            "required": ["table_name", "rows", "row_type"],
        },
    },
    {
        "name": "report_gap",
        "description": (
            "Record a coverage gap where a scenario step cannot be captured by any "
            "registered fried-plantains table. Gap analysis is required — call this for "
            "every attack step that has no matching table."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "scenario_step": {
                    "type": "string",
                    "description": "Description of the attack step that cannot be logged",
                },
                "mitre_technique": {
                    "type": "string",
                    "description": "MITRE ATT&CK technique ID, e.g. T1534",
                },
                "missing_table": {
                    "type": "string",
                    "description": "Name of the table that would be needed, e.g. TeamsMessageEvents",
                },
                "missing_source": {
                    "type": "string",
                    "description": "Security tool that would produce this log, e.g. Microsoft Purview",
                },
                "suggested_tools": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of tools that could provide coverage for this gap",
                },
                "impact": {
                    "type": "string",
                    "description": "Security impact of this logging gap — what attackers can do undetected",
                },
            },
            "required": [
                "scenario_step",
                "missing_table",
                "missing_source",
                "suggested_tools",
                "impact",
            ],
        },
    },
    {
        "name": "validate_rows",
        "description": (
            "Validate all rows for a table against its schema. Must be called on every "
            "table before calling finalize(). Returns any validation errors found. "
            "Fix all errors before proceeding — do not call finalize() with unvalidated rows."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "table_name": {
                    "type": "string",
                    "description": "Table name to validate",
                }
            },
            "required": ["table_name"],
        },
    },
    {
        "name": "finalize",
        "description": (
            "Write all generated rows to NDJSON and Parquet files and produce the run manifest. "
            "Only call this after validate_rows() has returned no errors for all tables. "
            "Can only be called once per agent run."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "One-paragraph summary of what was generated and any notable patterns",
                }
            },
            "required": ["summary"],
        },
    },
]


def _tool_get_table_schema(inp: dict, agent) -> dict:
    table_name = inp.get("table_name", "")
    if not table_name:
        return {"error": "table_name is required"}
    schema = agent.fp_schema.get(table_name)
    if schema is None:
        available = sorted(agent.fp_schema.keys())
        return {
            "error": f"Table '{table_name}' not found in schema. Available: {available}"
        }
    return {"table_name": table_name, "schema": schema}


def _tool_resolve_user(inp: dict, agent) -> dict:
    identifier = inp.get("identifier", "")
    if not identifier:
        return {"error": "identifier is required"}
    ctx = agent.resolver.get_user_context(identifier)
    if "error" in ctx:
        logger.warning("resolve_user failed: %s", ctx["error"])
        return ctx
    return {
        "username": ctx["username"],
        "display_name": ctx["display_name"],
        "email": ctx["email"],
        "upn": ctx["upn"],
        "department": ctx["department"],
        "account_name": ctx["account_name"],
        "account_domain": ctx["account_domain"],
        "account_upn": ctx["account_upn"],
        "device_name": ctx["device_name"],
        "device_id": ctx["device_id"],
        "device_fqdn": ctx["device_fqdn"],
        "normal_ip": ctx["ip_address"],
        "normal_login_hours": ctx["normal_login_hours"],
        "normal_login_days": ctx["normal_login_days"],
        "is_vip": ctx["is_vip"],
        "mfa_enrolled": ctx["mfa_enrolled"],
    }


def _tool_resolve_device(inp: dict, agent) -> dict:
    identifier = inp.get("identifier", "")
    if not identifier:
        return {"error": "identifier is required"}
    device = agent.resolver.resolve_device(identifier)
    if device is None:
        logger.warning("resolve_device: '%s' not found in CMDB", identifier)
        return {"error": f"Device '{identifier}' not found in CMDB"}
    return {
        "hostname": device.hostname,
        "device_id": device.device_id,
        "fqdn": device.fqdn,
        "os": device.os,
        "os_version": device.os_version,
        "ip_address": device.ip_address,
        "subnet": device.subnet,
        "managed": device.managed,
        "av_product": device.av_product,
        "asset_type": device.asset_type,
    }


def _tool_add_log_rows(inp: dict, agent) -> dict:
    from agent.core import MAX_ROWS_PER_CALL, MAX_ROWS_PER_TABLE

    table_name = inp.get("table_name", "")
    rows = inp.get("rows", [])
    row_type = inp.get("row_type", "bau")

    if not table_name:
        return {"error": "table_name is required"}
    if row_type not in ("bau", "malicious"):
        return {"error": "row_type must be 'bau' or 'malicious'"}
    if not isinstance(rows, list):
        return {"error": "rows must be a list"}

    if len(rows) > MAX_ROWS_PER_CALL:
        return {
            "error": (
                f"Too many rows in single call (max {MAX_ROWS_PER_CALL}). "
                f"Split into multiple calls."
            )
        }

    table_data = agent.generated_tables.setdefault(table_name, {"bau": [], "malicious": []})
    existing_count = sum(len(v) for v in table_data.values())
    if existing_count + len(rows) > MAX_ROWS_PER_TABLE:
        return {
            "error": (
                f"Table {table_name} would exceed {MAX_ROWS_PER_TABLE} rows. "
                f"Current: {existing_count}."
            )
        }

    table_data[row_type].extend(rows)
    return {
        "added": len(rows),
        "table": table_name,
        "row_type": row_type,
        "total_rows": existing_count + len(rows),
    }


def _tool_report_gap(inp: dict, agent) -> dict:
    gap = {
        "scenario_step": inp.get("scenario_step", ""),
        "mitre_technique": inp.get("mitre_technique"),
        "missing_table": inp.get("missing_table", ""),
        "missing_source": inp.get("missing_source", ""),
        "suggested_tools": inp.get("suggested_tools", []),
        "impact": inp.get("impact", ""),
    }
    if not gap["scenario_step"] or not gap["missing_table"]:
        return {"error": "scenario_step and missing_table are required"}
    agent.gaps.append(gap)
    return {"gap_recorded": True, "total_gaps": len(agent.gaps)}


def _tool_validate_rows(inp: dict, agent) -> dict:
    table_name = inp.get("table_name", "")
    if not table_name:
        return {"error": "table_name is required"}

    schema = agent.fp_schema.get(table_name, {})
    table_data = agent.generated_tables.get(table_name, {})
    all_rows = table_data.get("bau", []) + table_data.get("malicious", [])

    if not all_rows:
        return {"table": table_name, "valid": True, "errors": [], "row_count": 0}

    errors = _validate_rows(table_name, all_rows, schema)
    agent.validated_tables.add(table_name)
    return {
        "table": table_name,
        "valid": len(errors) == 0,
        "errors": errors,
        "row_count": len(all_rows),
    }


def _tool_finalize(inp: dict, agent) -> dict:
    if agent.finalized:
        return {"error": "finalize() has already been called for this run"}

    unvalidated = set(agent.generated_tables.keys()) - agent.validated_tables
    if unvalidated:
        return {
            "error": (
                f"Tables have not been validated: {sorted(unvalidated)}. "
                f"Call validate_rows() on each table before finalizing."
            )
        }

    summary = inp.get("summary", "")
    agent.finalized = True
    agent.finalize_summary = summary
    return {"finalized": True, "summary": summary}


# Dispatch table used by the agent loop
TOOL_HANDLERS = {
    "get_table_schema": _tool_get_table_schema,
    "resolve_user": _tool_resolve_user,
    "resolve_device": _tool_resolve_device,
    "add_log_rows": _tool_add_log_rows,
    "report_gap": _tool_report_gap,
    "validate_rows": _tool_validate_rows,
    "finalize": _tool_finalize,
}
