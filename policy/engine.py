"""
Policy Validation Engine — XploitAI (Phase 1)

Responsibilities (per architecture.md):
- Validate action ordering along the kill chain
- Enforce allowed transitions and reject invalid steps
- Validate state-dependent prerequisites deterministically

Non-Responsibilities:
- No execution logic
- No AI reasoning
- No direct state mutation

This engine operates on an immutable view of the current AttackState and an
Action proposal. It uses the actions registry for local precondition checks and
expected postconditions, then enforces global policy rules about ordering and
state transitions.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Mapping, MutableMapping, Optional, Protocol

from actions.predefined import (
    ExpectedPostconditions,
    get_action_definition,
)
from policy.approval import requires_human_approval

logger = logging.getLogger(__name__)


class AttackStateLike(Protocol):
    """Minimal interface required from the core AttackState.

    We avoid importing the Django model to keep policy engine decoupled and
    deterministic. The executor/orchestration will provide a concrete instance.
    """

    current_phase: str
    state_data: MutableMapping[str, Any]


@dataclass(frozen=True)
class PolicyDecision:
    """Represents the outcome of policy validation for a proposed action."""

    allowed: bool
    reason: str
    expected: Optional[ExpectedPostconditions] = None
    approval_required: bool = False


class PolicyEngine:
    """Deterministic policy validator for action proposals.

    Entry point: validate(name, state, parameters)
    """

    # Allowed next-phase transitions as an ordered progression
    _ORDER = (
        "RECONNAISSANCE",
        "ENUMERATION",
        "EXPLOITATION",
        "PRIVILEGE_ESCALATION",
        "PROOF_OF_COMPROMISE",
        "COMPLETED",
    )

    def __init__(self) -> None:
        # No dynamic configuration in Phase 1
        pass

    def validate(
        self,
        name: str,
        state: AttackStateLike,
        parameters: Mapping[str, Any],
    ) -> PolicyDecision:
        """Validate the proposed action against global policy rules.

        Steps:
        1) Resolve action definition
        2) Enforce local preconditions via the action definition
        3) Collect expected postconditions
        4) Enforce ordering rules across phases
        5) Enforce simple state prerequisites
        6) Check approval requirements
        """
        # Step 1: Resolve definition
        definition = get_action_definition(name)
        if definition is None:
            logger.info("Policy reject: unknown action '%s'", name)
            return PolicyDecision(False, "Unknown action definition")

        # Step 2: Local preconditions
        ok, reason = definition.validate_preconditions(state, parameters)
        if not ok:
            logger.info(
                "Policy reject: local preconditions failed for '%s' reason='%s'",
                name,
                reason,
            )
            return PolicyDecision(False, f"Preconditions failed: {reason}")

        # Step 3: Expected postconditions (for further checks)
        expected = definition.expected_postconditions(state, parameters)

        # Step 4: Ordering rules
        if not self._is_order_valid(state.current_phase, expected.phase_transition):
            logger.info(
                "Policy reject: invalid phase transition from '%s' to '%s'",
                state.current_phase,
                expected.phase_transition,
            )
            return PolicyDecision(False, "Invalid phase transition")

        # Step 5: State prerequisites
        prereq_ok, prereq_reason = self._check_state_prerequisites(
            action=name, state=state, params=parameters
        )
        if not prereq_ok:
            logger.info(
                "Policy reject: state prerequisites failed for '%s': %s",
                name,
                prereq_reason,
            )
            return PolicyDecision(False, prereq_reason)

        logger.debug(
            "Policy allow: '%s' in phase '%s' -> %s",
            name,
            state.current_phase,
            expected.phase_transition,
        )

        # Step 6: Check for Human Approval
        approval_required = requires_human_approval(state.current_phase, name)

        if approval_required:
            logger.warning(
                "APPROVAL GATE: Action '%s' in phase '%s' flagged for HUMAN APPROVAL.",
                name,
                state.current_phase,
            )

        return PolicyDecision(
            True, "Approved", expected, approval_required=approval_required
        )

    # -------------------
    # Internal helpers
    # -------------------

    def _is_order_valid(
        self, current_phase: str, next_phase: Optional[str]
    ) -> bool:
        """Enforce monotonic progression along the kill chain.

        - If next_phase is None: allow staying in the same phase
        - Otherwise: require that next_phase is exactly the successor or equal
          to current when the action does not advance.
        - COMPLETED is terminal; no further transitions allowed afterwards.
        """
        if current_phase not in self._ORDER:
            return False

        if current_phase == "COMPLETED":
            # No actions after completion in Phase 1
            return False

        if next_phase is None:
            return True

        try:
            idx = self._ORDER.index(current_phase)
            # allow staying in place or moving exactly one step forward
            allowed_next = {self._ORDER[idx]}
            if idx + 1 < len(self._ORDER):
                allowed_next.add(self._ORDER[idx + 1])
        except ValueError:
            return False

        return next_phase in allowed_next

    def _check_state_prerequisites(
        self,
        *,
        action: str,
        state: AttackStateLike,
        params: Mapping[str, Any],
    ) -> tuple[bool, str]:
        """Enforce minimal deterministic state prerequisites per action.

        These checks are intentionally simple for Phase 1 and avoid deep
        coupling. They validate that necessary prior data exists before
        allowing later-stage actions.
        """
        data = state.state_data or {}

        if action == "ServiceEnumeration":
            # Require passive recon domains present for enumeration
            recon = data.get("recon", {})
            domains = recon.get("domains", [])
            if not isinstance(domains, list) or not domains:
                return False, "Enumeration requires recon domains"
            return True, "OK"

        if action == "ExploitAttempt":
            enumeration = data.get("enumeration", {})
            services = enumeration.get("services", {})
            if not isinstance(services, dict) or not services:
                return False, "Exploit requires enumerated services"
            return True, "OK"

        if action == "PrivilegeEscalation":
            exploitation = data.get("exploitation", {})
            compromised = exploitation.get("compromised_hosts", {})
            if not isinstance(compromised, dict) or not compromised:
                return False, "Privilege escalation requires compromised host"
            return True, "OK"

        if action == "ProofOfCompromise":
            pe = data.get("privilege_escalation", {})
            if not isinstance(pe, dict) or not pe:
                return False, "Proof requires prior privilege escalation"
            return True, "OK"

        # Default: no extra prerequisites beyond local preconditions
        return True, "OK"


__all__ = [
    "PolicyEngine",
    "PolicyDecision",
]
