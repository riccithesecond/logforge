"""
Row validator for fried-plantains table schemas.
validate_rows() is called before finalize() — every table's rows must
pass validation before the agent is allowed to conclude the run.
"""
from datetime import datetime


def validate_rows(table_name: str, rows: list[dict], schema: dict) -> list[str]:
    """
    Validates generated rows against the fried-plantains table schema.
    Returns a list of error strings — empty list means all rows are valid.

    Checks:
    - Required columns are present (nullable=False columns, excluding ReportId)
    - No unknown column names (case-sensitive — DeviceName != devicename)
    - ActionType is from the table's defined enum
    - Timestamp is a parseable ISO 8601 UTC string
    """
    errors = []
    required_columns = {
        col["name"]
        for col in schema.get("columns", [])
        if not col.get("nullable", False) and col["name"] != "ReportId"
    }
    valid_columns = {col["name"] for col in schema.get("columns", [])}
    valid_action_types = set(schema.get("action_types", []))

    for i, row in enumerate(rows):
        row_errors = []

        missing = required_columns - set(row.keys())
        if missing:
            row_errors.append(f"Missing required columns: {sorted(missing)}")

        unknown = set(row.keys()) - valid_columns
        if unknown:
            row_errors.append(
                f"Unknown columns (check case-sensitivity): {sorted(unknown)}"
            )

        if "ActionType" in row and valid_action_types:
            if row["ActionType"] not in valid_action_types:
                row_errors.append(
                    f"Invalid ActionType '{row['ActionType']}'. "
                    f"Valid: {sorted(valid_action_types)}"
                )

        if "Timestamp" in row:
            try:
                datetime.fromisoformat(str(row["Timestamp"]).replace("Z", "+00:00"))
            except ValueError:
                row_errors.append(f"Invalid Timestamp: '{row['Timestamp']}'")

        if row_errors:
            errors.append(f"Row {i}: {'; '.join(row_errors)}")

    return errors
