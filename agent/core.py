"""
Main agent loop. Claude reasons about the scenario and calls tools to execute
mechanical work: schema lookup, CMDB resolution, row generation, validation, output.
Hard limits on iterations and token usage prevent runaway API costs.
"""
import json
import logging
import sys
from pathlib import Path

import anthropic
import click

from cmdb.loader import load_cmdb
from cmdb.resolver import CMDBResolver
from schema.loader import load_fp_schema
from agent.tools import TOOL_DEFINITIONS, TOOL_HANDLERS
from output.writer import write_run_output
from output.manifest import build_manifest

logger = logging.getLogger(__name__)

# Hard limits — do not change without updating tests
MAX_ITERATIONS = 50
MAX_INPUT_TOKENS = 180_000
WARN_TOKEN_THRESHOLD = 0.80
MAX_ROWS_PER_CALL = 10_000
MAX_ROWS_PER_TABLE = 50_000

SYSTEM_PROMPT = """
You are logforge, an expert security log generation agent. Your job is to generate
realistic, context-aware synthetic security logs for detection engineering testing.

You have access to tools for resolving CMDB entities, looking up table schemas,
generating log rows, reporting coverage gaps, validating output, and finalizing.

Your generation rules — follow these without exception:

1. CMDB-first: Before generating any row involving an internal user or device,
   call resolve_user() or resolve_device(). Use the returned values for DeviceName,
   DeviceId, AccountName, AccountDomain, and IP fields — never invent these values.
   The same user must always appear with the same device and IP unless the scenario
   explicitly requires deviation (impossible travel, lateral movement, etc.).

2. Schema accuracy: Call get_table_schema() for each table before generating rows.
   Column names are case-sensitive — DeviceName is not devicename. ActionType values
   must come from the table's defined enum exactly. Never invent column names.

3. Cross-table consistency: When an event spans multiple tables (a process that also
   makes a network connection), DeviceId, DeviceName, Timestamp, and InitiatingProcessId
   must be identical across all tables for that event.

4. Temporal realism: BAU events spread across normal business hours for the user's
   department. Attack events follow a realistic kill chain with appropriate dwell time
   between stages — seconds for automated steps, minutes to hours for manual ones.

5. Ratio discipline: bau_ratio defines the fraction of benign events. BAU events
   must look genuinely benign — real process names, legitimate URLs, normal auth.

6. Gap analysis: After planning the scenario, compare each attack step to the
   registered tables. If a step cannot be captured by any registered table, call
   report_gap() with the missing table name, source tool, and attacker impact.

7. Validate before finalizing: Call validate_rows() on every table's rows before
   calling finalize(). Fix any validation errors before proceeding.

Work through the scenario step by step:
- Call get_table_schema() for expected tables
- Plan the full timeline
- Resolve all CMDB entities
- Identify and report gaps
- Generate rows table by table using add_log_rows()
- Validate all tables
- Call finalize()
"""

# Known prompt injection patterns in external content
INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous",
    "disregard your instructions",
    "new instructions:",
    "system prompt:",
    "you are now",
    "forget everything",
    "ignore the above",
]


def sanitize_threat_intel(content: str) -> str:
    """
    Detects obvious prompt injection attempts in external content.
    Wraps content in XML tags so Claude treats it as data, not instructions.
    Claude's training causes it to respect the semantic boundary of XML document tags.
    Raises ValueError if injection patterns are detected — never silently passes.
    """
    content_lower = content.lower()
    for pattern in INJECTION_PATTERNS:
        if pattern in content_lower:
            raise ValueError(
                f"Threat intel content contains suspicious pattern: '{pattern}'. "
                f"Review the file manually before ingesting."
            )
    # XML wrapping is the primary mitigation — patterns above catch obvious attempts
    return f"<threat_intel_document>\n{content}\n</threat_intel_document>"


class LogForgeAgent:
    """
    Encapsulates a single logforge run. Holds all mutable state that tools
    read and write during the agent loop.
    """

    def __init__(
        self,
        cmdb_path: str,
        fp_schema: dict,
        run_id: str,
        skip_output_validation: bool = False,
    ):
        self.cmdb = load_cmdb(cmdb_path)
        self.resolver = CMDBResolver(self.cmdb)
        self.fp_schema = fp_schema
        self.run_id = run_id
        self.skip_output_validation = skip_output_validation

        # Mutable state written by tool functions
        self.generated_tables: dict[str, dict[str, list]] = {}
        self.gaps: list[dict] = []
        self.validated_tables: set[str] = set()
        self.finalized: bool = False
        self.finalize_summary: str = ""


async def run_agent(
    scenario_input: str,
    cmdb_path: str,
    threat_intel_path: str | None,
    fp_url: str,
    fp_token: str,
    model: str,
    api_key: str,
    run_id: str,
    skip_output_validation: bool = False,
) -> dict:
    """
    Entry point for a logforge agent run. Loads schemas, builds the user message,
    runs the agent loop, then writes output files and returns the manifest.
    """
    fp_schema = await load_fp_schema(fp_url, fp_token)
    agent = LogForgeAgent(
        cmdb_path=cmdb_path,
        fp_schema=fp_schema,
        run_id=run_id,
        skip_output_validation=skip_output_validation,
    )

    user_message = _build_user_message(scenario_input, threat_intel_path, agent)
    client = anthropic.Anthropic(api_key=api_key)
    messages = [{"role": "user", "content": user_message}]

    iteration = 0
    while True:
        iteration += 1
        if iteration > MAX_ITERATIONS:
            raise RuntimeError(
                f"Agent loop exceeded {MAX_ITERATIONS} iterations without calling "
                f"finalize(). This likely indicates a stuck tool call. "
                f"Check the last tool result for errors."
            )

        response = client.messages.create(
            model=model,
            max_tokens=8192,
            system=SYSTEM_PROMPT,
            tools=TOOL_DEFINITIONS,
            messages=messages,
        )

        # Warn on high token usage — do not silently approach the context limit
        if response.usage.input_tokens > MAX_INPUT_TOKENS * WARN_TOKEN_THRESHOLD:
            click.echo(
                f"Warning: high token usage ({response.usage.input_tokens} input tokens). "
                f"Consider reducing scenario complexity or CMDB size.",
                err=True,
            )

        messages.append({"role": "assistant", "content": response.content})

        if agent.finalized:
            break

        # Show tool calls in real time so the user can see what the agent is doing
        for block in response.content:
            if block.type == "tool_use":
                click.echo(f"  >> {block.name}({list(block.input.keys())})")
            elif block.type == "text" and block.text.strip():
                # Encode to ASCII with replacement so Windows cp1252 consoles don't crash
                safe = block.text.strip()[:120].encode("ascii", errors="replace").decode("ascii")
                click.echo(f"  [thinking] {safe}")

        if response.stop_reason == "end_turn":
            # Claude stopped without calling finalize — this is unexpected
            logger.warning(
                "Agent stopped at iteration %d without calling finalize(). "
                "Checking for generated content.",
                iteration,
            )
            if agent.generated_tables:
                # Force finalize with whatever was generated
                agent.finalized = True
                agent.finalize_summary = "Agent completed without explicit finalize call."
            break

        if response.stop_reason != "tool_use":
            break

        # Process tool calls and append results
        tool_results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            handler = TOOL_HANDLERS.get(block.name)
            if handler is None:
                result = {"error": f"Unknown tool: {block.name}"}
            else:
                try:
                    result = handler(block.input, agent)
                except Exception as exc:
                    # Catching here as a safety net — handlers should return error dicts
                    logger.error("Unexpected exception in tool %s: %s", block.name, exc)
                    result = {"error": f"Internal error in {block.name}: {str(exc)}"}

            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": json.dumps(result),
            })

        messages.append({"role": "user", "content": tool_results})

    # Write output files and build manifest
    output_dir = Path("output") / "runs" / run_id
    output_files = write_run_output(agent.generated_tables, run_id, output_dir)
    manifest = build_manifest(
        run_id=run_id,
        scenario_input=scenario_input,
        agent=agent,
        output_files=output_files,
        fp_url=fp_url,
    )
    return manifest


def _build_user_message(
    scenario_input: str,
    threat_intel_path: str | None,
    agent: LogForgeAgent,
) -> str:
    """
    Constructs the user message passed to Claude. Scenarios and threat intel are
    wrapped in XML tags — they are data to reason about, not instructions to follow.
    """
    parts = []

    # Provide CMDB summary as context (counts only — no PII in the message)
    cmdb = agent.cmdb
    from datetime import datetime, timezone
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    parts.append(
        f"<environment_summary>\n"
        f"Organization: {cmdb.organization}\n"
        f"Users: {len(cmdb.users)}, Workstations: {len(cmdb.devices)}, "
        f"Servers: {len(cmdb.servers)}\n"
        f"Domain: {cmdb.network.domain} ({cmdb.network.netbios_domain})\n"
        f"Registered tables: {', '.join(cmdb.infrastructure.registered_tables) or 'loaded from API'}\n"
        f"Today's date: {today} — all generated Timestamps must fall on or before this date.\n"
        f"</environment_summary>"
    )

    # Scenario input — could be a YAML file path (already loaded) or freeform text
    if Path(scenario_input).exists() and scenario_input.endswith((".yaml", ".yml")):
        scenario_text = Path(scenario_input).read_text(encoding="utf-8")
        parts.append(f"<scenario>\n{scenario_text}\n</scenario>")
    else:
        parts.append(f"<scenario>\n{scenario_input}\n</scenario>")

    # Threat intel — sanitized before inclusion
    if threat_intel_path:
        raw_content = Path(threat_intel_path).read_text(encoding="utf-8")
        sanitized = sanitize_threat_intel(raw_content)
        parts.append(sanitized)

    parts.append(
        "Generate realistic synthetic security logs for this scenario. "
        "Follow all generation rules from your system prompt. "
        "Begin by calling get_table_schema() for the relevant tables."
    )

    return "\n\n".join(parts)
