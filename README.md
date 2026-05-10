# logforge

**Context-aware synthetic security log generation for detection engineering.**

logforge takes a scenario — a YAML attack plan, freeform text, or a threat intel report — and produces schema-accurate, entity-consistent synthetic logs for every affected detection platform table. It also identifies logging gaps: attack steps that no registered table can capture. Both outputs feed directly into detection engineering work.

---

## What problem does it solve?

Detection engineers need realistic log data to write, test, and tune detections. Production logs contain PII and are usually unavailable in dev environments. Generic test data doesn't exercise real detection logic — it lacks the entity consistency and temporal realism that detections depend on.

logforge generates logs that:
- Reference real entities from your environment CMDB (same user always has the same workstation, device ID, and IP across all tables)
- Follow realistic attack timelines (seconds for automated steps, minutes to hours for manual attacker activity)
- Match the exact schema of your detection platform tables (column names are case-sensitive, ActionType values come from defined enums)
- Interleave benign BAU activity with malicious events in the correct ratio

---

## Architecture — how the agent loop works

```
Scenario + CMDB
      │
      ▼
┌─────────────────────────────────────────────────────┐
│                   agent/core.py                     │
│                                                     │
│  Claude (model set via CLAUDE_MODEL in .env)        │
│    reasons about the scenario                       │
│    decides what to generate                         │
│    calls tools to execute mechanical work           │
│                                                     │
│  Tool handlers (agent/tools.py):                    │
│    get_table_schema()  → fetch column definitions   │
│    resolve_user()      → CMDB lookup by username    │
│    resolve_device()    → CMDB lookup by hostname    │
│    add_log_rows()      → append rows to table       │
│    report_gap()        → record coverage gap        │
│    validate_rows()     → check rows against schema  │
│    finalize()          → signal generation complete │
└─────────────────────────────────────────────────────┘
      │
      ▼
output/writer.py → NDJSON.gz + Parquet per table
output/manifest.py → run manifest with attack timeline
output/shipper.py → POST to fried-plantains ingest API
```

Claude reasons; tools execute. Claude never writes files or makes HTTP calls directly — it calls tools which do the mechanical work. This keeps Claude's context focused on generation quality while tool implementations handle schema validation, file I/O, and API calls.

The loop has a hard limit of 50 iterations (`MAX_ITERATIONS`) and warns at 80% of the 180k token context window. Both limits are enforced before any API call completes.

---

## The CMDB — why entity consistency matters

Detection engineers write rules like:
```
DeviceProcessEvents
| where InitiatingProcessAccountName == "jsmith"
| join DeviceNetworkEvents on DeviceId, Timestamp
```

These join-based detections break if the same user appears with different device IDs across tables, or if a network event has a different timestamp than the process that caused it. logforge enforces entity consistency by loading your environment CMDB at startup and routing every user/device lookup through `CMDBResolver` before any field values are chosen.

The same user always appears with the same:
- `AccountName`, `AccountDomain`, `AccountUpn`
- `DeviceName`, `DeviceId`, `DeviceFqdn`
- Source IP (from `normal_source_ips`)

Deviation is only allowed when the scenario explicitly requires it (impossible travel, lateral movement to a different host, stolen credentials used from a new IP).

---

## Gap analysis — what it produces and why it matters

Not every attack step can be captured by your current detection stack. logforge identifies these gaps and reports them explicitly. After planning the scenario timeline, Claude compares each attack step against the list of registered fried-plantains tables. If a step has no matching table, it calls `report_gap()` with:

- The missing table name (e.g., `TeamsMessageEvents`)
- The security tool that would produce it (e.g., `Microsoft Purview`)
- Suggested tools that could provide coverage
- The security impact of the gap

Example gap report output:

```
Coverage gaps from: 20240115_143022

  Step:    Attacker sends lateral phishing via Microsoft Teams
  MITRE:   T1534
  Missing: TeamsMessageEvents (Microsoft Purview)
  Tools:   Microsoft Purview, Defender XDR
  Impact:  Teams lateral phishing is completely invisible — no table captures
           internal Teams messages, so an attacker can use Teams for C2 and
           lateral movement without triggering any detection.

  Step:    Attacker calls IAM GetAccountAuthorizationDetails
  MITRE:   T1580
  Missing: AWSCloudTrailEvents (AWS CloudTrail)
  Tools:   AWS CloudTrail, AWS Security Hub
  Impact:  Cloud credential enumeration leaves no trace — CloudTrail is not
           ingested into fried-plantains, so cloud-based privilege escalation
           reconnaissance is a blind spot.
```

Gap analysis is not optional — it ships in every run's manifest alongside the generated logs.

---

## Quick start

**1. Set up the environment**

```bash
git clone https://github.com/riccithesecond/logforge.git
cd logforge
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python check_deps.py        # must pass before any commit
```

**2. Configure credentials**

```bash
cp .env.example .env
# Edit .env — add your ANTHROPIC_API_KEY and FP_API_TOKEN
```

**3. Populate the CMDB**

Edit `cmdb/environment.json` with your environment's real users and devices. The starter template has two Finance users (`jsmith`, `cthompson`) and two workstations. Never commit this file — it's in `.gitignore`.

**4. Run the BEC scenario**

```bash
python main.py generate -s scenarios/examples/bec-executive-impersonation.yaml
```

Output appears in `output/runs/YYYYMMDD_HHMMSS/`. View gaps:

```bash
python main.py gaps
```

Ship to fried-plantains:

```bash
python main.py generate -s scenarios/examples/bec-executive-impersonation.yaml --ship
```

---

## Example manifest — attack_timeline section

```json
{
  "run_id": "20240115_143022",
  "generated_at": "2024-01-15T14:30:22.441Z",
  "scenario": "bec-executive-impersonation",
  "attack_timeline": [
    {
      "table": "ProofpointMessageEvents",
      "timestamp": "2024-01-15T09:00:00.000Z",
      "action_type": "MessageDelivered",
      "summary": "ProofpointMessageEvents MessageDelivered on CORP-WS-042 by jsmith — Spoofed CFO wire transfer request"
    },
    {
      "table": "AbnormalThreatEvents",
      "timestamp": "2024-01-15T09:00:44.000Z",
      "action_type": "ThreatDetected",
      "summary": "AbnormalThreatEvents ThreatDetected — Executive Impersonation, impostor score 98"
    },
    {
      "table": "ProofpointClickEvents",
      "timestamp": "2024-01-15T09:23:11.000Z",
      "action_type": "ClickPermitted",
      "summary": "ProofpointClickEvents ClickPermitted on CORP-WS-042 by jsmith → https://attacker-infrastructure.com/track"
    }
  ],
  "coverage_gaps": [
    {
      "scenario_step": "Attacker follows up via Teams to pressure for wire transfer",
      "mitre_technique": "T1534",
      "missing_table": "TeamsMessageEvents",
      "missing_source": "Microsoft Purview",
      "suggested_tools": ["Microsoft Purview", "Defender XDR"],
      "impact": "Teams lateral phishing leaves no trace in current stack"
    }
  ],
  "ingest_commands": [
    "python main.py ship --file output/runs/20240115_143022/ProofpointMessageEvents_20240115_143022.ndjson.gz --table ProofpointMessageEvents"
  ]
}
```

---

## CLI reference

```
python main.py generate [OPTIONS]

  Generate synthetic logs for a scenario.

  Options:
    -s, --scenario TEXT         Path to scenario YAML or freeform description (required)
    -c, --cmdb TEXT             Path to CMDB JSON [default: cmdb/environment.json]
    -t, --threat-intel TEXT     Path to threat intel report (.txt, .md, .pdf)
    -d, --days INT              Days the attack spans ending today (prompted if omitted)
    --fp-url TEXT               fried-plantains URL (overrides .env)
    --ship                      Ship to fried-plantains after generation
    --skip-output-validation    Skip injection scan on output rows

python main.py ship [OPTIONS]

  Ship a previously generated NDJSON file to fried-plantains.

  Options:
    -f, --file TEXT    Path to .ndjson.gz file (required)
    -t, --table TEXT   Target table name (required)
    --fp-url TEXT      fried-plantains URL (overrides .env)
    --skip-output-validation

python main.py gaps

  Print coverage gaps from the most recent run.
```

---

## Security notes

**Prompt injection protection.** Threat intel reports are untrusted external content that could contain adversarial text. Before including any file content in Claude's context, `sanitize_threat_intel()` scans for known injection patterns (`"ignore previous instructions"`, `"system prompt:"`, etc.) and raises `ValueError` on detection. Content is always wrapped in `<threat_intel_document>` XML tags — Claude's training causes it to treat XML-wrapped content as data to reason about, not instructions to follow. Both mitigations apply; neither alone is sufficient.

**Agent loop limits.** An unconstrained agentic loop can exhaust API credits. logforge enforces a hard limit of 50 iterations and warns at 80% of the 180k input token context window. Both limits are in `agent/core.py` as named constants tested by the test suite.

**File input validation.** Every CLI file argument passes through `validate_input_file()` before being opened. It checks: file existence, regular file (not symlink or directory), allowed extension by argument type, file size under 10MB, and path containment within the project directory (prevents `../../etc/passwd` style attacks).

**Output injection scanning.** Generated rows are scanned for patterns that could be interpreted as injection attacks against fried-plantains before shipping (`'; DROP`, `OR 1=1`, `../`, `${`, `<script`, etc.). The `--skip-output-validation` flag allows override for scenarios that intentionally generate exploit strings — it always prints a warning to stderr.

**HTTP security.** The httpx client in `output/shipper.py` is always configured with `verify=True` and `follow_redirects=False`. Redirect following is permanently disabled because a redirect could forward `FP_API_TOKEN` to an attacker-controlled host. Both settings are tested by `test_httpx_client_no_redirects`. Files are uploaded as multipart form data; `table` and `source` are sent as URL query parameters (not form fields) to match the fried-plantains ingest API signature.

**Secret hygiene.** `ANTHROPIC_API_KEY` and `FP_API_TOKEN` are loaded exclusively from `.env` via pydantic-settings. `os.environ` is never read directly. Secrets never appear in log output, `click.echo()`, or exception messages. The CMDB may contain real usernames, emails, and IPs — only counts are logged, never field values.

**Dependency audit.** `check_deps.py` runs `pip-audit` against `requirements.txt` and exits 1 if any vulnerability is found. Run it before every commit. The test suite does not substitute for this — `check_deps.py` must pass independently.

---

## Roadmap

- **Threat intel PDF parsing** — extract structured IOCs and TTPs from PDF reports using PyMuPDF, feeding them directly into the scenario planner
- **STIX/TAXII feed input** — consume threat intelligence from TAXII servers to auto-generate scenarios from live feed data
- **Web UI for gap reports** — interactive gap report browser showing MITRE coverage heat map overlaid on the scenario kill chain
- **Multi-tenant CMDB** — support multiple environment JSON files for generating cross-environment scenarios (e.g., contractor lateral movement between org A and org B)
- **Streaming output** — stream rows to fried-plantains in real time as they are generated rather than batching at finalize
