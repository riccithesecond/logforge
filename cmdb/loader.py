"""
CMDB JSON loader. Validates all fields on load via Pydantic and cross-checks
that every user's workstation hostname exists in the devices list.
Never logs CMDB contents — logs only counts to avoid leaking PII.
"""
import json
from pathlib import Path
from cmdb.schema import CMDB


def load_cmdb(path_str: str) -> CMDB:
    """
    Loads and validates the CMDB JSON file.
    Pydantic validates all fields on load — invalid CMDB raises ValidationError
    with a clear message before the agent runs.
    Never logs CMDB contents — logs only counts.
    """
    path = Path(path_str)
    if not path.exists():
        raise FileNotFoundError(
            f"CMDB file not found: {path_str}\n"
            f"Copy cmdb/environment.json.example to cmdb/environment.json "
            f"and populate it with your environment details."
        )
    raw = json.loads(path.read_text(encoding="utf-8"))
    cmdb = CMDB(**raw)

    # Log counts only — never log emails, IPs, or usernames
    print(
        f"CMDB loaded: {len(cmdb.users)} users, "
        f"{len(cmdb.devices)} workstations, "
        f"{len(cmdb.servers)} servers"
    )

    # Validate cross-references — every user's workstation must exist
    device_hostnames = {d.hostname for d in cmdb.devices} | {s.hostname for s in cmdb.servers}
    for user in cmdb.users:
        if user.workstation and user.workstation not in device_hostnames:
            raise ValueError(
                f"CMDB validation error: user '{user.username}' references "
                f"workstation '{user.workstation}' which is not in the devices list."
            )
    return cmdb
