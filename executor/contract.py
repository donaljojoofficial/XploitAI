"""
Execution Contract — XploitAI

Defines the data structures and protocols for communication between
the XploitAI Controller (Django) and the Executor Daemon (Kali Linux).

This contract ensures that:
1. The Executor receives all necessary context (command, limits, params).
2. The Controller receives structured results (stdout, stderr, artifacts).
3. Both sides agree on status codes and failure modes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class ExecutionStatus:
    """Standard status codes for execution tasks."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"


@dataclass
class ExecutionRequest:
    """
    Payload delivered to the Executor Daemon.
    Represents a single unit of work (shell command).
    """
    task_id: str
    action_name: str
    command: str
    parameters: Dict[str, Any]
    limits: Dict[str, Any]  # e.g., {'timeout': 60, 'memory_mb': 128}

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for API response."""
        return {
            "task_id": self.task_id,
            "action_name": self.action_name,
            "command": self.command,
            "parameters": self.parameters,
            "limits": self.limits,
        }


@dataclass
class ExecutionResult:
    """
    Payload returned by the Executor Daemon.
    Contains the raw output and metadata of the execution.
    """
    task_id: str
    status: str  # Must be one of ExecutionStatus
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    error_message: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ExecutionResult:
        """Deserialize from API request data."""
        return cls(
            task_id=data["task_id"],
            status=data["status"],
            exit_code=data.get("exit_code", -1),
            stdout=data.get("stdout", ""),
            stderr=data.get("stderr", ""),
            duration_seconds=data.get("duration_seconds", 0.0),
            artifacts=data.get("artifacts", []),
            error_message=data.get("error_message"),
        )

    def is_success(self) -> bool:
        """Check if the execution was successful (exit code 0)."""
        return self.status == ExecutionStatus.COMPLETED and self.exit_code == 0