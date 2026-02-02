"""
State adapter placeholder.

Responsibility
- Translate core domain objects (e.g., AttackState) into AI-readable request
  structures consumed by the decision engine.

Constraints
- Structure only: no transformation logic yet.
- Import-safe: no side effects, I/O, or external dependencies.

Design Notes
- Keep the adapter interface narrow and explicit to reduce coupling with the
  core domain model. The schemas.DecisionRequest object will serve as the
  canonical input for the decision engine.
"""
from __future__ import annotations

from typing import Protocol

from .schemas import DecisionRequest


class StateAdapter(Protocol):
    """Protocol for adapting core state into a DecisionRequest.

    Concrete implementations will be added later.
    """

    def to_decision_request(self, state: object) -> DecisionRequest:  # pragma: no cover - placeholder
        """Convert a core state object into a DecisionRequest.

        For now, `state` is typed as object to avoid coupling to core models.
        Later, this can be refined with a narrow interface or pydantic schema.
        """
        ...
