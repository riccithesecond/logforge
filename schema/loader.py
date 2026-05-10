"""
fried-plantains table schema loader. Fetches schemas from the API and caches
the result locally so logforge can run offline or when FP is unavailable.
Never logs the API token — logs only the URL and table count.
"""
import httpx
import json
from pathlib import Path

CACHE_PATH = Path(__file__).parent / "cache" / "fp_schema.json"


async def load_fp_schema(fp_base_url: str, api_token: str) -> dict:
    """
    Fetches registered table schemas from fried-plantains API.
    Falls back to local cache if API is unreachable.
    Cache is written on every successful fetch — keeps it current.
    Never logs the token value.
    """
    try:
        async with httpx.AsyncClient(
            verify=True,
            follow_redirects=False,
            timeout=httpx.Timeout(connect=10.0, read=30.0),
        ) as client:
            resp = await client.get(
                f"{fp_base_url}/api/v1/schema/tables",
                headers={"Authorization": f"Bearer {api_token}"},
            )
            resp.raise_for_status()
            schema = resp.json()
            CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            CACHE_PATH.write_text(json.dumps(schema, indent=2))
            print(f"Schema loaded: {len(schema)} tables from fried-plantains API")
            return schema
    except Exception as e:
        if CACHE_PATH.exists():
            print(f"Warning: Could not reach fried-plantains ({e}). Using cached schema.")
            return json.loads(CACHE_PATH.read_text())
        raise RuntimeError(
            f"Could not load schema from API and no cache exists. "
            f"Ensure fried-plantains is running and FP_BASE_URL is correct."
        ) from e
