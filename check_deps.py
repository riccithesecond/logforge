#!/usr/bin/env python3
"""
Run pip-audit and fail if any vulnerabilities exist.
Usage: python check_deps.py
Exit code 0 = clean. Exit code 1 = findings or error.
"""
import subprocess
import sys
import json

import shutil
import os

pip_audit_cmd = shutil.which("pip-audit")
if pip_audit_cmd is None:
    # Fall back to running pip-audit via the same Python interpreter
    pip_audit_cmd = [sys.executable, "-m", "pip_audit"]
else:
    pip_audit_cmd = [pip_audit_cmd]

result = subprocess.run(
    pip_audit_cmd + ["--format", "json", "--requirement", "requirements.txt"],
    capture_output=True,
    text=True,
)

try:
    data = json.loads(result.stdout)
except json.JSONDecodeError:
    print("pip-audit did not return valid JSON. Is pip-audit installed?")
    sys.exit(1)

vulnerable = [
    dep for dep in data.get("dependencies", [])
    if dep.get("vulns")
]

if vulnerable:
    print(f"pip-audit: {len(vulnerable)} vulnerable package(s) found:\n")
    for dep in vulnerable:
        for vuln in dep["vulns"]:
            fix = vuln.get("fix_versions", ["no fix available"])
            print(f"  {dep['name']} {dep['version']}: {vuln['id']} — fix: {fix}")
    print("\nResolve before committing.")
    sys.exit(1)

print(f"pip-audit: clean ({len(data.get('dependencies', []))} packages checked).")
