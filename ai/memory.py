"""
Agent memory placeholder.

Responsibility
- Define interfaces for storing and retrieving prior decisions, observations,
  and outcomes for the AI agent.

Constraints
- No storage implementation or persistence logic.
- Import-safe; no I/O on import.

Future Considerations
- Pluggable backends (in-memory, database, file-based) with strict boundaries.
- Retention policies and security constraints will be documented and enforced
  alongside real implementations.
"""
from __future__ import annotations

from typing import Protocol, Iterable, Optional

from .schemas import MemoryRecord


class AgentMemory(Protocol):
    """Protocol for AI agent memory interactions.

    Implementations will be responsible for persistence and retrieval policies.
    """

    def add(self, record: MemoryRecord) -> None:  # pragma: no cover - placeholder
        """Add a memory record to the store."""
        ...

    def query(self, limit: Optional[int] = None) -> Iterable[MemoryRecord]:  # pragma: no cover - placeholder
        """Query recent memory records, optionally limited by count."""
        ...
