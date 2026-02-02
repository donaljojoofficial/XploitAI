"""
Decision engine placeholder.

Responsibility
- Defines the entry-point abstraction for the future AI decision process that
  will choose actions within the XploitAI system.

Constraints
- No business logic is implemented here.
- Import-safe: no side effects, I/O, or SDK imports.

Usage (future)
- The core orchestrator will construct an implementation and call evaluate().
- The evaluate() method is specified for typing only; implementations will live
  alongside this module or in submodules of ai/.
"""
from __future__ import annotations

from typing import Any, Mapping, Optional, Protocol

from .schemas import DecisionRequest, Decision


class DecisionEngine(Protocol):
    """Protocol describing the AI decision engine interface.

    This provides a stable boundary for the runtime layer without committing to
    a concrete implementation.
    """

    def evaluate(self, request: DecisionRequest, context: Optional[Mapping[str, Any]] = None) -> Decision:  # pragma: no cover - placeholder
        """Evaluate a decision request and return a decision object.

        Implementations must be side-effect free in terms of module import. The
        method itself will be implemented later.
        """
        ...
