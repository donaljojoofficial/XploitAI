"""
Schemas for AI runtime data structures.

Purpose
- Provide minimal, import-safe typed structures for data exchanged within the
  AI runtime layer (e.g., requests, decisions, memory records).
- Define a deterministic, JSON-serializable decision input schema representing
  what the AI is allowed to see.

Constraints
- No validation frameworks or external dependencies are used.
- Keep structures lightweight and side-effect free.
- This module defines data contracts only. No business logic or SDK calls.

Why dataclasses?
- Dataclasses are chosen over Pydantic to avoid adding dependencies at this
  stage and to preserve minimal import cost. These dataclasses are designed to
  contain JSON-serializable primitives (str, int, float, bool, None) and nested
  lists/mappings so they can be serialized using dataclasses.asdict() followed by
  json.dumps() when needed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional, List, Dict, Protocol

from actions.predefined import ExpectedPostconditions


@dataclass(frozen=True)
class KnownService:
    """Minimal description of a service the AI is allowed to know about.

    Fields
    - name: Human-readable identifier for the service (e.g., "web_app").
    - endpoint: Optional endpoint/location string (e.g., URL or host:port).
      Must not expose secrets or internal credentials.
    - protocol: Optional protocol descriptor (e.g., "http", "ssh").
    - metadata: Optional JSON-serializable metadata that does not leak sensitive
      details. Keep minimal and sanitized.
    """

    name: str
    endpoint: Optional[str] = None
    protocol: Optional[str] = None
    metadata: Optional[Mapping[str, Any]] = None


@dataclass(frozen=True)
class PastActionSummary:
    """Summary of a prior action taken by the agent.

    Fields
    - action_type: Canonical action name used by the system (e.g., "scan_port").
    - parameters: JSON-serializable parameters used for the action.
    - phase: Optional phase during which the action occurred (e.g., "recon").
    - timestamp: Optional ISO-8601 timestamp string when the action was taken.
    """

    action_type: str
    parameters: Mapping[str, Any]
    phase: Optional[str] = None
    timestamp: Optional[str] = None


@dataclass(frozen=True)
class ActionResultSummary:
    """Summary of the most recent action result visible to the AI.

    Fields
    - success: Whether the action was considered successful.
    - output_summary: Optional short, sanitized description of the outcome.
    - raw_output: Optional actual command stdout (truncated to 1500 chars).
    - error: Optional error message if the action failed.
    """

    success: bool
    output_summary: Optional[str] = None
    raw_output: Optional[str] = None
    error: Optional[str] = None


@dataclass(frozen=True)
class DecisionInput:
    """Deterministic input schema for the decision engine.

    This represents WHAT the AI can see at decision time, not WHAT it should do.
    It is intentionally minimal and JSON-serializable.

    Fields
    - phase: Current system/attack phase visible to the AI (e.g., "init",
      "recon", "exploit", "post_exploit").
    - known_services: List of services explicitly exposed to the AI. Do not
      include secrets, credentials, or internal-only details.
    - past_actions: Minimal history of previous actions the AI took, including
      parameters. Keep summaries sanitized.
    - last_result: Optional summary of the last action's outcome.
    """

    phase: str
    known_services: List[KnownService]
    past_actions: List[PastActionSummary]
    available_commands: Optional[List[Dict[str, Any]]] = None
    last_result: Optional[ActionResultSummary] = None
    findings: Optional[Mapping[str, Any]] = None
    memory: Optional[Mapping[str, Any]] = None


@dataclass(frozen=True)
class DecisionRequest:
    """Structured request wrapper passed to the decision engine.

    Fields
    - decision_input: The canonical, JSON-serializable state representation the
      AI is allowed to see.
    - context: Optional auxiliary metadata (e.g., correlation ids). Must be
      JSON-serializable if persisted or logged.
    """

    decision_input: DecisionInput
    context: Optional[Mapping[str, Any]] = None


@dataclass(frozen=True)
class Decision:
    """Structured decision output from the decision engine.

    Placeholder for future action selection output.
    """

    action_type: str
    parameters: Mapping[str, Any]
    rationale: Optional[str] = None
    suggested_next_phase: Optional[str] = None
    phase_reason: Optional[str] = None


@dataclass(frozen=True)
class PlanStep:
    """A single step within a multi-step plan."""

    step_number: int
    action_type: str
    parameters: Mapping[str, Any]
    rationale: str
    stage_label: Optional[str] = None
    execution_type: str = "command"
    planned_command: Optional[str] = None
    shell_command: Optional[str] = None
    command: Optional[str] = None
    script_language: Optional[str] = None
    script_content: Optional[str] = None
    artifact_refs: Optional[List[Dict[str, Any]]] = None
    success_criteria: Optional[str] = None


@dataclass(frozen=True)
class Plan:
    """An ordered list of recommended actions."""

    steps: List[PlanStep]
    rationale: Optional[str] = None


@dataclass(frozen=True)
class MemoryRecord:
    """Record of a past decision and outcome for memory storage."""

    request: DecisionRequest
    decision: Decision
    
    # Policy Outcome
    policy_allowed: bool
    policy_reason: Optional[str] = None

    # Execution Outcome (if policy allowed)
    execution_success: Optional[bool] = None
    execution_output: Optional[str] = None
    
    # Metadata
    timestamp: Optional[str] = None


# --- Integration Schemas ---


class PolicyDecisionLike(Protocol):
    """A protocol for the structure returned by PolicyEngine.validate.

    This avoids a direct dependency from the `ai` module to `policy.schemas`
    while still allowing for type checking.
    """

    allowed: bool
    reason: str
    expected: Optional[ExpectedPostconditions]


@dataclass(frozen=True)
class ValidatedDecision:
    """A composite object that holds an AI-generated decision and the result of
    its validation by the policy engine.
    """

    ai_decision: Decision
    policy_decision: PolicyDecisionLike

    @property
    def approved(self) -> bool:
        """Convenience property to check if the action was approved."""
        return self.policy_decision.allowed
