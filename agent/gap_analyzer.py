"""
Coverage gap detection helpers. Gap analysis compares the scenario's attack steps
against registered fried-plantains tables to identify logging blind spots.
Gap reporting is required — it is a primary output alongside the generated logs.
"""
from typing import Optional


# Tables that exist in fried-plantains and can capture log data
# This is populated at runtime from the schema API response
KNOWN_TABLES: set[str] = set()


def find_gap(
    step_description: str,
    tables_affected: list[str],
    registered_tables: set[str],
) -> Optional[dict]:
    """
    Returns a gap dict if any of the step's affected tables are not registered,
    or None if all affected tables are covered.
    """
    missing = [t for t in tables_affected if t not in registered_tables]
    if not missing:
        return None
    return {
        "scenario_step": step_description,
        "missing_tables": missing,
    }


def format_gap_report(gaps: list[dict]) -> str:
    """Format the gap list for display in the CLI gaps command."""
    if not gaps:
        return "No coverage gaps detected."
    lines = [f"{len(gaps)} coverage gap(s) detected:\n"]
    for gap in gaps:
        lines.append(f"  Step:    {gap['scenario_step']}")
        if gap.get("mitre_technique"):
            lines.append(f"  MITRE:   {gap['mitre_technique']}")
        lines.append(f"  Missing: {gap['missing_table']} ({gap['missing_source']})")
        lines.append(f"  Tools:   {', '.join(gap['suggested_tools'])}")
        lines.append(f"  Impact:  {gap['impact']}\n")
    return "\n".join(lines)
