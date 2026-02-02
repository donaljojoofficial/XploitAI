"""
AI Runtime package for XploitAI.

This package defines the structural scaffolding for the future AI agent runtime.
It intentionally contains no executable logic and performs no side effects on import.

Exports:
- Public type aliases and minimal stubs to support import-time references without
  binding to concrete implementations yet. This provides a stable surface for
  other layers to reference in a type-safe manner.

Security & Safety:
- No network calls, file I/O, model loading, or process execution.
- Keep imports minimal and safe. Only standard library typing tools are used.
"""
from __future__ import annotations

from typing import Protocol, Any, Mapping, Optional


class DecisionEngine(Protocol):
    """Protocol for the future AI decision engine.

    This is a minimal interface for type-hinting only. Implementations will be
    provided later within this package. Do not add behavior here.
    """

    def evaluate(self, request: Any, context: Optional[Mapping[str, Any]] = None) -> Any:  # pragma: no cover - placeholder
        """Evaluate a decision request and return a structured decision.

        Parameters
        - request: Structured input produced by state adapters.
        - context: Optional auxiliary metadata.

        Returns
        - A structured decision object defined in ai.schemas.Decision.
        """
        ...


__all__ = [
    "DecisionEngine",
]
