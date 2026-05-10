"""
fried-plantains ingest API shipper. Hardened httpx client — verify=True and
follow_redirects=False are permanent requirements. A redirect could forward
FP_API_TOKEN to an attacker-controlled host. Output rows are scanned for
injection patterns before shipping unless --skip-output-validation is passed.
"""
import gzip
import json
import logging
from pathlib import Path

import httpx
import click

logger = logging.getLogger(__name__)

# Patterns that could be interpreted as injection attacks against fried-plantains
SUSPICIOUS_OUTPUT_PATTERNS = [
    "<script",
    "javascript:",
    "data:text/html",
    "../",
    "..\\",
    "'; DROP",
    "1=1--",
    "OR 1=1",
    "${",
    "#{",
    "{{",
]


def validate_output_rows(rows: list[dict]) -> None:
    """
    Scans generated rows for injection patterns before shipping to fried-plantains.
    Attack scenarios may intentionally generate exploit strings — if this causes
    false positives, pass --skip-output-validation (prints a warning to stderr).
    Raises ValueError on detection — never silently passes.
    """
    for i, row in enumerate(rows):
        for field, value in row.items():
            if not isinstance(value, str):
                continue
            for pattern in SUSPICIOUS_OUTPUT_PATTERNS:
                if pattern.lower() in value.lower():
                    raise ValueError(
                        f"Row {i} field '{field}' contains suspicious pattern "
                        f"'{pattern}'. Use --skip-output-validation to override."
                    )


async def ship_to_fried_plantains(
    ndjson_gz_path: str,
    table_name: str,
    fp_base_url: str,
    fp_api_token: str,
    skip_validation: bool = False,
) -> dict:
    """
    POSTs a gzipped NDJSON file to the fried-plantains ingest API.
    Validates all rows for injection patterns before sending unless
    skip_validation=True (caller must print a warning to stderr in that case).
    Logs table name and row count only — never logs the token.
    """
    path = Path(ndjson_gz_path)
    if not path.exists():
        return {"error": f"File not found: {ndjson_gz_path}"}

    # Read and optionally validate rows before shipping
    rows = []
    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))

    if skip_validation:
        click.echo(
            "Warning: output validation skipped — rows not scanned for injection patterns.",
            err=True,
        )
    else:
        validate_output_rows(rows)

    source_type = _table_to_source_type(table_name)
    url = f"{fp_base_url}/api/v1/ingest/upload"

    # Never log the token — log URL, method, table, and row count only
    logger.info("POST %s — table: %s, rows: %d", url, table_name, len(rows))

    async with httpx.AsyncClient(
        verify=True,                   # never verify=False
        follow_redirects=False,        # a redirect could forward FP_API_TOKEN to another host
        timeout=httpx.Timeout(120.0, connect=10.0),
        limits=httpx.Limits(max_connections=5, max_keepalive_connections=2),
    ) as client:
        with open(path, "rb") as f:
            resp = await client.post(
                url,
                headers={"Authorization": f"Bearer {fp_api_token}"},
                # table and source are query parameters in the FastAPI endpoint,
                # not Form() fields — send them in the URL, not the multipart body.
                params={"source": "mde_native", "table": table_name},
                files={"file": (path.name, f, "application/x-ndjson")},
            )

    if resp.status_code not in (200, 201, 202):
        return {
            "error": f"Ingest API returned {resp.status_code}",
            "table": table_name,
        }

    return {
        "shipped": True,
        "table": table_name,
        "rows": len(rows),
        "status_code": resp.status_code,
    }


def _table_to_source_type(table_name: str) -> str:
    """Map fried-plantains table names to SOURCE_TYPES keys from backend/parsers/__init__.py."""
    mapping = {
        "DeviceProcessEvents": "defender",
        "DeviceNetworkEvents": "defender",
        "DeviceFileEvents": "defender",
        "DeviceLogonEvents": "defender",
        "DeviceRegistryEvents": "defender",
        "DeviceEvents": "defender",
        "DeviceAlertEvents": "defender",
        "ProofpointMessageEvents": "proofpoint_tap",
        "ProofpointClickEvents": "proofpoint_tap",
        "AbnormalThreatEvents": "abnormal_threats",
        "AbnormalCaseEvents": "abnormal_cases",
        "ZscalerWebEvents": "zscaler_web",
        "ZscalerDnsEvents": "zscaler_dns",
        "AWSCloudTrailEvents": "cloudtrail",
        "CloudflareHttpEvents": "cloudflare",
        "CloudflareFirewallEvents": "cloudflare",
        "CloudflareDnsEvents": "cloudflare",
        "IdentityLogonEvents": "defender",
        "CloudAppEvents": "defender",
    }
    return mapping.get(table_name, "defender")
