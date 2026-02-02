"""
Agent memory implementation.

Responsibility
- Store and retrieve prior decisions, observations, and outcomes.
- Maintain a bounded history to influence future decisions.

Constraints
- In-memory only (Phase 3).
- Bounded size (deque).
- No external database dependencies.
"""
from __future__ import annotations

from collections import deque
from typing import Protocol, Iterable, Optional, List

from .schemas import MemoryRecord


class AgentMemory(Protocol):
    """Protocol for AI agent memory interactions."""

    def add(self, record: MemoryRecord) -> None:  # pragma: no cover - placeholder
        """Add a memory record to the store."""
        ...

    def query(self, limit: Optional[int] = None) -> Iterable[MemoryRecord]:  # pragma: no cover - placeholder
        """Query recent memory records, optionally limited by count."""
        ...

    def clear(self) -> None:  # pragma: no cover - placeholder
        """Clear all memory records."""
        ...

    def count_attempts(self, action_type: str) -> int:  # pragma: no cover - placeholder
        """Count how many times a specific action type has been attempted."""
        ...


class RuntimeAgentMemory:
    """Concrete in-memory implementation of AgentMemory.

    Attributes:
        capacity (int): Maximum number of records to keep.
    """

    def __init__(self, capacity: int = 50) -> None:
        self._capacity = capacity
        self._store: deque[MemoryRecord] = deque(maxlen=capacity)

    def add(self, record: MemoryRecord) -> None:
        """Add a record to the rolling memory window."""
        self._store.append(record)

    def query(self, limit: Optional[int] = None) -> List[MemoryRecord]:
        """Retrieve recent records (oldest to newest)."""
        all_records = list(self._store)
        if limit is not None and limit > 0:
            return all_records[-limit:]
        return all_records

    def clear(self) -> None:
        """Reset the memory store."""
        self._store.clear()

    def count_attempts(self, action_type: str) -> int:
        """Count occurrences of an action type in the current memory."""
        return sum(1 for r in self._store if r.decision.action_type == action_type)
