"""
Scenario data models. Scenarios describe the attack and BAU activity
the agent must simulate. They are passed as structured context to Claude —
never embedded in the system prompt.
"""
from pydantic import BaseModel, field_validator
from typing import Optional


class ScenarioStep(BaseModel):
    step_number: int
    description: str
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    actor: str
    target: Optional[str] = None
    tables_affected: list[str] = []
    time_offset_minutes: int = 0
    requires_cmdb_entity: bool = True


class Scenario(BaseModel):
    name: str
    description: str
    mitre_techniques: list[str]
    actor_type: str = "external"
    initial_access_vector: str = "unknown"
    start_time: Optional[str] = None
    duration_hours: int = 4
    bau_ratio: float = 0.95
    target_users: list[str] = []
    target_devices: list[str] = []
    steps: list[ScenarioStep] = []
    freeform_description: Optional[str] = None
    threat_intel_file: Optional[str] = None

    @field_validator("bau_ratio")
    @classmethod
    def ratio_in_range(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"bau_ratio must be between 0.0 and 1.0, got {v}")
        return v

    @field_validator("actor_type")
    @classmethod
    def valid_actor_type(cls, v: str) -> str:
        allowed = {"external", "insider", "compromised_account"}
        if v not in allowed:
            raise ValueError(f"actor_type must be one of {allowed}, got '{v}'")
        return v
