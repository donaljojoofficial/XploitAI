"""
Rule-Based Detection Engine for the Defender AI.

This engine evaluates observations of attacker actions against a static set of
rules to identify and flag potentially malicious behavior.
"""
from __future__ import annotations

from typing import Optional

from .defender_schemas import (
    DefenderDetection,
    DefenderObservation,
    DetectionSeverity,
)


class DefenderEngine:
    """A simple, rule-based engine for detecting suspicious activity."""

    def evaluate(
        self, observation: DefenderObservation
    ) -> Optional[DefenderDetection]:
        """
        Evaluate an observation against a set of hardcoded detection rules.

        Args:
            observation: The event seen by the defender.

        Returns:
            A DefenderDetection if a rule is matched, otherwise None.
        """
        # Rule: Detect successful exploitation attempts
        if (
            observation.action_name == "exploit_service"
            and observation.outcome == "SUCCESS"
        ):
            return DefenderDetection(
                rule_id="detect-successful-exploit",
                severity=DetectionSeverity.HIGH,
                description=f"A successful exploit was performed against a service.",
                observation=observation,
            )

        # Rule: Detect any privilege escalation activity
        if observation.phase == "PRIVILEGE_ESCALATION":
            return DefenderDetection(
                rule_id="detect-privilege-escalation",
                severity=DetectionSeverity.CRITICAL,
                description=f"Activity related to privilege escalation was detected: {observation.action_name}",
                observation=observation,
            )

        return None