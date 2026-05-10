"""
NDJSON and Parquet output writer. All rows are sorted by Timestamp before writing
so output files are in realistic chronological order. Parquet writes are atomic
(write to .tmp then rename) to prevent partial files if the process is interrupted.
"""
import gzip
import json
import logging
import os
from pathlib import Path
from datetime import datetime, timezone

import pyarrow as pa
import pyarrow.parquet as pq

logger = logging.getLogger(__name__)


def write_run_output(
    generated_tables: dict[str, dict[str, list]],
    run_id: str,
    output_dir: Path,
) -> dict[str, dict]:
    """
    Writes NDJSON.gz and Parquet files for each generated table.
    Returns a dict mapping table_name → {ndjson_path, parquet_path, row_counts}.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    output_files = {}

    for table_name, table_data in generated_tables.items():
        bau_rows = table_data.get("bau", [])
        malicious_rows = table_data.get("malicious", [])
        all_rows = bau_rows + malicious_rows

        if not all_rows:
            continue

        # Sort by Timestamp for chronological order — realistic log ordering
        all_rows = sorted(
            all_rows,
            key=lambda r: r.get("Timestamp", ""),
        )

        ndjson_path = output_dir / f"{table_name}_{run_id}.ndjson.gz"
        parquet_path = output_dir / f"{table_name}_{run_id}.parquet"

        _write_ndjson(all_rows, ndjson_path)
        _write_parquet(all_rows, parquet_path)

        output_files[table_name] = {
            "ndjson_path": str(ndjson_path),
            "parquet_path": str(parquet_path),
            "row_counts": {
                "total": len(all_rows),
                "bau": len(bau_rows),
                "malicious": len(malicious_rows),
            },
        }
        logger.info(
            "Wrote %s: %d total rows (%d bau, %d malicious)",
            table_name,
            len(all_rows),
            len(bau_rows),
            len(malicious_rows),
        )

    return output_files


def _write_ndjson(rows: list[dict], path: Path) -> None:
    with gzip.open(path, "wt", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, default=_json_default) + "\n")


def _write_parquet(rows: list[dict], path: Path) -> None:
    if not rows:
        return

    # Collect all column names across rows to handle sparse schemas
    all_keys = list(dict.fromkeys(k for row in rows for k in row.keys()))
    columns: dict[str, list] = {k: [] for k in all_keys}
    for row in rows:
        for key in all_keys:
            val = row.get(key)
            # Coerce lists and dicts to JSON strings for Parquet compatibility
            if isinstance(val, (list, dict)):
                val = json.dumps(val)
            columns[key].append(val)

    table = pa.table({k: pa.array(v) for k, v in columns.items()})

    # Atomic write — prevents partial Parquet files on interruption
    tmp_path = path.with_suffix(".parquet.tmp")
    pq.write_table(table, tmp_path, compression="snappy")
    os.replace(tmp_path, path)


def _json_default(obj):
    """JSON serialiser for types not handled by stdlib json."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
