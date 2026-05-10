"""Tests for fried-plantains table schema row validation."""


def test_valid_row_passes():
    from schema.validator import validate_rows
    schema = {
        "columns": [
            {"name": "Timestamp", "dtype": "TIMESTAMP", "nullable": False},
            {"name": "DeviceId", "dtype": "STRING", "nullable": False},
            {"name": "DeviceName", "dtype": "STRING", "nullable": False},
            {"name": "ActionType", "dtype": "STRING", "nullable": False},
            {"name": "ReportId", "dtype": "STRING", "nullable": False},
        ],
        "action_types": ["ProcessCreated"],
    }
    rows = [
        {
            "Timestamp": "2024-01-15T09:00:00+00:00",
            "DeviceId": "dev-001",
            "DeviceName": "CORP-WS-042",
            "ActionType": "ProcessCreated",
            "ReportId": "r1",
        }
    ]
    assert validate_rows("DeviceProcessEvents", rows, schema) == []


def test_invalid_action_type_caught():
    from schema.validator import validate_rows
    schema = {
        "columns": [{"name": "ActionType", "dtype": "STRING", "nullable": False}],
        "action_types": ["ProcessCreated"],
    }
    rows = [{"ActionType": "INVENTED_VALUE"}]
    errors = validate_rows("T", rows, schema)
    assert any("Invalid ActionType" in e for e in errors)


def test_case_sensitive_column_detection():
    from schema.validator import validate_rows
    schema = {
        "columns": [{"name": "DeviceName", "dtype": "STRING", "nullable": False}],
        "action_types": [],
    }
    rows = [{"devicename": "CORP-WS-042"}]  # wrong case
    errors = validate_rows("T", rows, schema)
    assert any("Unknown columns" in e for e in errors)
    assert any("Missing required columns" in e for e in errors)


def test_invalid_timestamp_caught():
    from schema.validator import validate_rows
    schema = {
        "columns": [{"name": "Timestamp", "dtype": "TIMESTAMP", "nullable": False}],
        "action_types": [],
    }
    rows = [{"Timestamp": "not-a-timestamp"}]
    errors = validate_rows("T", rows, schema)
    assert any("Invalid Timestamp" in e for e in errors)
