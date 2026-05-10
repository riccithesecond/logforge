"""
Log row generation helpers. These are utility functions used by tool handlers —
Claude drives the actual generation decisions via tool calls, but these helpers
provide common patterns (timestamp generation, process field population, etc.)
"""
from datetime import datetime, timezone, timedelta
import random
import uuid


def generate_timestamp(base_time: datetime, offset_seconds: int = 0) -> str:
    """Return an ISO 8601 UTC timestamp with optional offset from a base time."""
    ts = base_time + timedelta(seconds=offset_seconds)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def new_process_id() -> int:
    """Generate a realistic Windows process ID (4–65535, multiples of 4)."""
    return random.randint(1, 16383) * 4


def new_report_id() -> str:
    """Generate a unique ReportId in the MDE format."""
    return str(uuid.uuid4()).replace("-", "").upper()


def bau_start_time(login_hours: str, date: datetime) -> datetime:
    """
    Parse a 'HH:MM-HH:MM' login hours string and return a datetime within that range.
    Used to place BAU events inside the user's normal working hours.
    """
    start_str, _ = login_hours.split("-")
    h, m = map(int, start_str.split(":"))
    base = date.replace(hour=h, minute=m, second=0, microsecond=0, tzinfo=timezone.utc)
    # Add a random offset within the first 4 hours of the login window
    return base + timedelta(minutes=random.randint(0, 240))
