"""
Schemas for the Defender AI.

This module defines the data structures used for observing the attack
environment and providing input to the defender AI engine.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Mapping


@dataclass(frozen=True)
class DefenderObservation:
    """
    A structured representation of a single, observable event for the Defender AI.

    This schema captures the essential details of a completed attacker action,
    providing a signal for detection engines to analyze. It represents what the
    defender "sees" at a specific moment in time.
    """
    event_type: str  # e.g., "ACTION_COMPLETED", "STATE_CHANGE"
    timestamp: datetime
    phase: str
    action_name: str
    action_parameters: Mapping[str, Any] = field(default_factory=dict)
    outcome: str  # e.g., "SUCCESS", "FAILURE"
    message: str = ""


class DetectionSeverity(str, Enum):
    """Severity levels for defender detections."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class DefenderDetection:
    """
    Represents a detection made by the Defender AI.

    This is the output of the defender engine, signaling that a potentially
    malicious event has been identified.
    """
    rule_id: str  # e.g., "detection-of-successful-exploit"
    severity: DetectionSeverity
    description: str
    observation: DefenderObservation