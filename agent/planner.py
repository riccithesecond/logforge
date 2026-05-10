"""
Scenario parsing and event timeline planning helpers.
Used by the agent to convert a YAML scenario into a structured event sequence
before passing it to Claude for log generation.
"""
from pathlib import Path
from typing import Optional

import yaml

from scenarios.schema import Scenario


def load_scenario(path: str) -> Scenario:
    """Load and validate a YAML scenario file."""
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return Scenario(**raw)


def summarize_scenario(scenario: Scenario) -> str:
    """
    Produce a concise text summary of the scenario for Claude's context.
    Does not expose internal Python objects — returns plain text only.
    """
    lines = [
        f"Scenario: {scenario.name}",
        f"Description: {scenario.description}",
        f"Actor type: {scenario.actor_type}",
        f"Initial access: {scenario.initial_access_vector}",
        f"Duration: {scenario.duration_hours}h",
        f"BAU ratio: {scenario.bau_ratio:.0%}",
        f"MITRE techniques: {', '.join(scenario.mitre_techniques)}",
        f"Target users: {', '.join(scenario.target_users) or 'none specified'}",
    ]
    if scenario.steps:
        lines.append(f"\nAttack steps ({len(scenario.steps)}):")
        for step in scenario.steps:
            mitre = f" [{step.mitre_technique}]" if step.mitre_technique else ""
            tables = f" → {', '.join(step.tables_affected)}" if step.tables_affected else ""
            lines.append(
                f"  {step.step_number}. +{step.time_offset_minutes}m "
                f"{step.description}{mitre}{tables}"
            )
    return "\n".join(lines)
