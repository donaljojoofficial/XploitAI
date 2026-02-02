"""
Schemas for AI runtime data structures.

Purpose
- Provide minimal, import-safe typed structures for data exchanged within the
  AI runtime layer (e.g., requests, decisions, memory records).

Constraints
- No validation frameworks or external dependencies are used.
- Keep structures lightweight and side-effect free.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional


@dataclass(frozen=True)
class DecisionRequest:
    """Structured input to the decision engine.

    Fields are intentionally generic until the adapter contracts are finalized.
    """

    state_summary: Mapping[str, Any]
    context: Optional[Mapping[str, Any]] = None


@dataclass(frozen=True)
class Decision:
    """Structured decision output from the decision engine.

    Placeholder for future action selection output.
    """

    action_type: str
    parameters: Mapping[str, Any]
    rationale: Optional[str] = None


@dataclass(frozen=True)
class MemoryRecord:
    """Record of a past decision and outcome for memory storage."""

    request: DecisionRequest
    decision: Decision
    outcome: Optional[Mapping[str, Any]] = None
