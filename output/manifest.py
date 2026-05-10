"""
Manifest builder. The manifest is the primary output artifact — it documents
what was generated, the attack timeline, coverage gaps, and ingest commands.
A detection engineer uses the manifest to understand the run without reading raw logs.
"""
import json
from datetime import datetime, timezone
from pathlib import Path


def build_manifest(
    run_id: str,
    scenario_input: str,
    agent,
    output_files: dict,
    fp_url: str,
) -> dict:
    """
    Builds the run manifest dict and writes it to the run directory.
    Returns the manifest dict so the CLI can print a summary.
    """
    generated_at = datetime.now(timezone.utc).isoformat()

    # Collect all malicious rows sorted by Timestamp for the attack timeline
    attack_timeline = []
    for table_name, table_data in agent.generated_tables.items():
        for row in table_data.get("malicious", []):
            attack_timeline.append({
                "table": table_name,
                "timestamp": row.get("Timestamp", ""),
                "action_type": row.get("ActionType", ""),
                "summary": _row_summary(table_name, row),
            })
    attack_timeline.sort(key=lambda e: e["timestamp"])

    # Build ingest commands for each generated file
    ingest_commands = []
    for table_name, file_info in output_files.items():
        ingest_commands.append(
            f"python main.py ship --file {file_info['ndjson_path']} --table {table_name}"
        )

    # Scenario summary — use the file path or truncate freeform text
    if Path(scenario_input).exists():
        scenario_summary = Path(scenario_input).stem
    else:
        scenario_summary = scenario_input[:200]

    manifest = {
        "run_id": run_id,
        "generated_at": generated_at,
        "scenario": scenario_summary,
        "tables_generated": output_files,
        "attack_timeline": attack_timeline,
        "coverage_gaps": agent.gaps,
        "ingest_commands": ingest_commands,
        "agent_summary": agent.finalize_summary,
    }

    # Write manifest alongside the generated files
    output_dir = Path("output") / "runs" / run_id
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / f"manifest_{run_id}.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    return manifest


def _row_summary(table_name: str, row: dict) -> str:
    """Produce a one-line human-readable summary of a log row for the timeline."""
    action = row.get("ActionType", "")
    device = row.get("DeviceName", "")
    account = row.get("AccountName", row.get("InitiatingProcessAccountName", ""))
    filename = row.get("FileName", row.get("ProcessCommandLine", ""))
    remote_ip = row.get("RemoteIP", "")
    url = row.get("RequestUri", row.get("UrlChain", ""))

    parts = [table_name]
    if action:
        parts.append(action)
    if device:
        parts.append(f"on {device}")
    if account:
        parts.append(f"by {account}")
    if filename:
        fn = str(filename)[:60]
        parts.append(f"— {fn}")
    elif remote_ip:
        parts.append(f"→ {remote_ip}")
    elif url:
        u = str(url)[:80]
        parts.append(f"→ {u}")

    return " ".join(parts)
