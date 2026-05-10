"""
logforge CLI entrypoint. All file arguments are validated before being opened —
validate_input_file() checks existence, extension, size, and path containment.
"""
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import click

from config import settings


def validate_input_file(path_str: str, allowed_extensions: list[str]) -> Path:
    """
    Validates a CLI file path before reading.
    Checks: existence, regular file (not symlink/directory),
    allowed extension, within project directory, under 10MB.
    Raises click.BadParameter on any violation.
    """
    path = Path(path_str).resolve()
    project_root = Path(__file__).parent.resolve()

    if not path.exists():
        raise click.BadParameter(f"File not found: {path_str}")
    if path.is_symlink():
        raise click.BadParameter(f"Symlinks not allowed: {path_str}")
    if not path.is_file():
        raise click.BadParameter(f"Not a regular file: {path_str}")
    if path.suffix.lower() not in allowed_extensions:
        raise click.BadParameter(
            f"File type not allowed. Expected one of: {allowed_extensions}"
        )
    if path.stat().st_size > 10 * 1024 * 1024:
        raise click.BadParameter(f"File too large (max 10MB): {path_str}")
    # Prevent path traversal outside the project directory
    try:
        path.relative_to(project_root)
    except ValueError:
        raise click.BadParameter(
            f"File must be within the project directory: {path_str}"
        )
    return path


@click.group()
def cli():
    """logforge — context-aware security log generation agent"""
    pass


@cli.command()
@click.option(
    "--scenario", "-s", required=True,
    help="Path to scenario YAML, or freeform description in quotes",
)
@click.option(
    "--cmdb", "-c", default="cmdb/environment.json",
    help="Path to CMDB JSON file",
)
@click.option(
    "--threat-intel", "-t", default=None,
    help="Path to threat intel report (.txt, .md, .pdf)",
)
@click.option(
    "--fp-url", default=None,
    help="fried-plantains base URL (overrides .env FP_BASE_URL)",
)
@click.option(
    "--ship", is_flag=True, default=False,
    help="Ship generated files to fried-plantains after generation",
)
@click.option(
    "--skip-output-validation", is_flag=True, default=False,
    help="Skip injection check on output rows (use for exploit-string scenarios)",
)
def generate(scenario, cmdb, threat_intel, fp_url, ship, skip_output_validation):
    """
    Generate synthetic logs for a scenario.

    \b
    Examples:
      python main.py generate -s scenarios/examples/bec-executive-impersonation.yaml
      python main.py generate -s "phishing leads to credential theft" --ship
      python main.py generate -s scenarios/examples/ransomware-deployment.yaml \\
          -t scenarios/threat_intel/report.txt
    """
    validated_cmdb = validate_input_file(cmdb, [".json"])

    scenario_path = None
    if Path(scenario).exists():
        validated_scenario = validate_input_file(scenario, [".yaml", ".yml"])
        scenario_path = str(validated_scenario)

    validated_ti = None
    if threat_intel:
        validated_ti = validate_input_file(threat_intel, [".txt", ".md", ".pdf"])

    effective_fp_url = fp_url or settings.FP_BASE_URL
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    asyncio.run(
        _run_generate(
            scenario_input=scenario_path or scenario,
            cmdb_path=str(validated_cmdb),
            threat_intel_path=str(validated_ti) if validated_ti else None,
            fp_url=effective_fp_url,
            ship=ship,
            skip_output_validation=skip_output_validation,
            run_id=run_id,
        )
    )


async def _run_generate(
    scenario_input: str,
    cmdb_path: str,
    threat_intel_path: str | None,
    fp_url: str,
    ship: bool,
    skip_output_validation: bool,
    run_id: str,
) -> None:
    from agent.core import run_agent

    click.echo(f"Starting logforge run {run_id}")
    manifest = await run_agent(
        scenario_input=scenario_input,
        cmdb_path=cmdb_path,
        threat_intel_path=threat_intel_path,
        fp_url=fp_url,
        fp_token=settings.FP_API_TOKEN,
        model=settings.CLAUDE_MODEL,
        api_key=settings.ANTHROPIC_API_KEY,
        run_id=run_id,
        skip_output_validation=skip_output_validation,
    )

    click.echo(f"\nRun complete: {run_id}")
    for table_name, file_info in manifest.get("tables_generated", {}).items():
        counts = file_info["row_counts"]
        click.echo(
            f"  {table_name}: {counts['total']} rows "
            f"({counts['bau']} bau, {counts['malicious']} malicious)"
        )

    gaps = manifest.get("coverage_gaps", [])
    if gaps:
        click.echo(f"\n{len(gaps)} coverage gap(s) detected — run 'python main.py gaps' to view")

    output_dir = Path("output") / "runs" / run_id
    click.echo(f"\nOutput: {output_dir}")

    if ship:
        await _ship_manifest(manifest, fp_url, skip_output_validation)


async def _ship_manifest(manifest: dict, fp_url: str, skip_output_validation: bool) -> None:
    from output.shipper import ship_to_fried_plantains

    for table_name, file_info in manifest.get("tables_generated", {}).items():
        result = await ship_to_fried_plantains(
            ndjson_gz_path=file_info["ndjson_path"],
            table_name=table_name,
            fp_base_url=fp_url,
            fp_api_token=settings.FP_API_TOKEN,
            skip_validation=skip_output_validation,
        )
        if "error" in result:
            click.echo(f"Ship failed for {table_name}: {result['error']}", err=True)
        else:
            click.echo(f"Shipped {table_name}: {result['rows']} rows")


@cli.command()
@click.option("--file", "-f", required=True, help="Path to NDJSON.gz file")
@click.option("--table", "-t", required=True, help="Target fried-plantains table name")
@click.option("--fp-url", default=None)
@click.option(
    "--skip-output-validation", is_flag=True, default=False,
)
def ship(file, table, fp_url, skip_output_validation):
    """Ship a previously generated NDJSON file to fried-plantains."""
    validated_file = validate_input_file(file, [".gz"])
    effective_fp_url = fp_url or settings.FP_BASE_URL
    asyncio.run(_ship(str(validated_file), table, effective_fp_url, skip_output_validation))


async def _ship(file: str, table: str, fp_url: str, skip_output_validation: bool) -> None:
    from output.shipper import ship_to_fried_plantains

    result = await ship_to_fried_plantains(
        ndjson_gz_path=file,
        table_name=table,
        fp_base_url=fp_url,
        fp_api_token=settings.FP_API_TOKEN,
        skip_validation=skip_output_validation,
    )
    if "error" in result:
        click.echo(f"Error: {result['error']}", err=True)
        sys.exit(1)
    click.echo(f"Shipped {table}: {result['rows']} rows (status {result['status_code']})")


@cli.command()
def gaps():
    """Print coverage gaps from the most recent run."""
    runs = sorted(Path("output/runs").glob("*/manifest_*.json"), reverse=True)
    if not runs:
        click.echo("No runs found in output/runs/")
        return
    manifest = json.loads(runs[0].read_text(encoding="utf-8"))
    gaps_list = manifest.get("coverage_gaps", [])
    if not gaps_list:
        click.echo("No coverage gaps in most recent run.")
        return
    click.echo(f"\nCoverage gaps from: {manifest['run_id']}\n")
    for gap in gaps_list:
        click.echo(f"  Step:    {gap['scenario_step']}")
        if gap.get("mitre_technique"):
            click.echo(f"  MITRE:   {gap['mitre_technique']}")
        click.echo(f"  Missing: {gap['missing_table']} ({gap['missing_source']})")
        click.echo(f"  Tools:   {', '.join(gap['suggested_tools'])}")
        click.echo(f"  Impact:  {gap['impact']}\n")


if __name__ == "__main__":
    cli()
