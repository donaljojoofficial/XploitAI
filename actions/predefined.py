"""
Action Registry with Predefined Actions for XploitAI (Phase 1)

This module defines a static registry of simulation-only actions. Each action
specifies:
- name and description
- allowed kill-chain phases
- required parameters
- deterministic preconditions validation
- expected postconditions (for the simulation executor to apply)

STRICTLY NO execution logic is included here. This aligns with:
- architecture.md: actions/ contains definitions, preconditions, postconditions only
- project_scope.md: simulation only, no real attack execution
- coding_standards.md: explicit, typed, logged decisions

The registry is static and deterministic.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional, Protocol


logger = logging.getLogger(__name__)


class AttackStateLike(Protocol):
    """Minimal interface required from the core AttackState.

    This avoids importing Django models at import time while still enabling
    type checking and keeping responsibilities decoupled.
    """

    current_phase: str
    state_data: MutableMapping[str, Any]


@dataclass(frozen=True)
class ExpectedPostconditions:
    """Describes deterministic effects an action expects upon success.

    The Simulation Executor will read this structure to update state and, if
    allowed by policy, transition to a next phase. This module does NOT perform
    any state mutation.
    """

    phase_transition: Optional[str] = None
    state_updates: Mapping[str, Any] = field(default_factory=dict)


class ActionDefinition(ABC):
    """Abstract base for all predefined actions.

    Subclasses must provide deterministic validation and postcondition
    expectations. No execution logic is allowed.
    """

    name: str
    description: str
    allowed_phases: frozenset[str]
    required_parameters: tuple[str, ...]

    def __init__(
        self,
        name: str,
        description: str,
        allowed_phases: Iterable[str],
        required_parameters: Iterable[str],
    ) -> None:
        self.name = name
        self.description = description
        self.allowed_phases = frozenset(allowed_phases)
        self.required_parameters = tuple(required_parameters)

    def _validate_common(
        self,
        state: AttackStateLike,
        parameters: Mapping[str, Any],
    ) -> tuple[bool, str]:
        """Validate phase and presence of required parameters deterministically."""
        logger.debug("Validating common preconditions for action '%s'", self.name)

        if state is None:
            logger.warning("State is None for action '%s'", self.name)
            return False, "Invalid state reference"

        if not isinstance(parameters, Mapping):
            logger.warning("Parameters not a mapping for action '%s'", self.name)
            return False, "Parameters must be a mapping"

        if state.current_phase not in self.allowed_phases:
            logger.info(
                "Action '%s' not allowed in phase '%s'",
                self.name,
                state.current_phase,
            )
            return False, f"Action not allowed in phase {state.current_phase}"

        missing = [p for p in self.required_parameters if p not in parameters]
        if missing:
            logger.info(
                "Action '%s' missing required parameters: %s",
                self.name,
                ", ".join(missing),
            )
            return False, f"Missing required parameters: {', '.join(missing)}"

        return True, "OK"

    @abstractmethod
    def validate_preconditions(
        self,
        state: AttackStateLike,
        parameters: Mapping[str, Any],
    ) -> tuple[bool, str]:
        """Subclasses implement additional deterministic precondition checks."""

    @abstractmethod
    def expected_postconditions(
        self,
        state: AttackStateLike,
        parameters: Mapping[str, Any],
    ) -> ExpectedPostconditions:
        """Describe expected state updates and potential phase transition."""


# -----------------------
# Predefined Action Types
# -----------------------


class PassiveRecon(ActionDefinition):
    """Simulated passive reconnaissance of a target domain.

    Parameters:
    - target_domain: str
    """

    def __init__(self) -> None:
        super().__init__(
            name="PassiveRecon",
            description=(
                "Collect publicly available information about a target domain "
                "without active interaction. Simulation-only."
            ),
            allowed_phases=["RECONNAISSANCE"],
            required_parameters=["target_domain"],
        )

    def validate_preconditions(
        self, state: AttackStateLike, parameters: Mapping[str, Any]
    ) -> tuple[bool, str]:
        ok, reason = self._validate_common(state, parameters)
        if not ok:
            return ok, reason

        target = parameters.get("target_domain")
        if not isinstance(target, str) or not target:
            logger.info("Invalid 'target_domain' for PassiveRecon: %r", target)
            return False, "Parameter 'target_domain' must be a non-empty string"

        return True, "OK"

    def expected_postconditions(
        self, state: AttackStateLike, parameters: Mapping[str, Any]
    ) -> ExpectedPostconditions:
        target = str(parameters.get("target_domain", "")).strip()
        updates: Dict[str, Any] = {
            "recon": {
                "domains": list({target}),  # deterministic set -> list
            }
        }
        logger.debug(
            "PassiveRecon expected postconditions for '%s': %s", target, updates
        )
        return ExpectedPostconditions(
            phase_transition="ENUMERATION",
            state_updates=updates,
        )


class ServiceEnumeration(ActionDefinition):
    """Simulated enumeration of services on a known host.

    Parameters:
    - target_host: str
    """

    def __init__(self) -> None:
        super().__init__(
            name="ServiceEnumeration",
            description=(
                "Enumerate exposed services on a known host using simulated data."
            ),
            allowed_phases=["ENUMERATION"],
            required_parameters=["target_host"],
        )

    def validate_preconditions(
        self, state: AttackStateLike, parameters: Mapping[str, Any]
    ) -> tuple[bool, str]:
        ok, reason = self._validate_common(state, parameters)
        if not ok:
            return ok, reason

        host = parameters.get("target_host")
        if not isinstance(host, str) or not host:
            logger.info("Invalid 'target_host' for ServiceEnumeration: %r", host)
            return False, "Parameter 'target_host' must be a non-empty string"

        return True, "OK"

    def expected_postconditions(
        self, state: AttackStateLike, parameters: Mapping[str, Any]
    ) -> ExpectedPostconditions:
        host = str(parameters.get("target_host", "")).strip()
        updates: Dict[str, Any] = {
            "enumeration": {
                "services": {
                    host: [
                        {"port": 80, "service": "http"},
                        {"port": 22, "service": "ssh"},
                    ]
                }
            }
        }
        logger.debug(
            "ServiceEnumeration expected postconditions for '%s': %s", host, updates
        )
        return ExpectedPostconditions(
            phase_transition="EXPLOITATION",
            state_updates=updates,
        )


class ExploitAttempt(ActionDefinition):
    """Simulated exploit attempt against a known service.

    Parameters:
    - target_host: str
    - vulnerability_id: str
    """

    def __init__(self) -> None:
        super().__init__(
            name="ExploitAttempt",
            description=(
                "Attempt a simulated exploit against an identified vulnerability "
                "on a target host."
            ),
            allowed_phases=["EXPLOITATION"],
            required_parameters=["target_host", "vulnerability_id"],
        )

    def validate_preconditions(
        self, state: AttackStateLike, parameters: Mapping[str, Any]
    ) -> tuple[bool, str]:
        ok, reason = self._validate_common(state, parameters)
        if not ok:
            return ok, reason

        host = parameters.get("target_host")
        vuln = parameters.get("vulnerability_id")

        if not isinstance(host, str) or not host:
            logger.info("Invalid 'target_host' for ExploitAttempt: %r", host)
            return False, "Parameter 'target_host' must be a non-empty string"
        if not isinstance(vuln, str) or not vuln:
            logger.info("Invalid 'vulnerability_id' for ExploitAttempt: %r", vuln)
            return False, "Parameter 'vulnerability_id' must be a non-empty string"

        return True, "OK"

    def expected_postconditions(
        self, state: AttackStateLike, parameters: Mapping[str, Any]
    ) -> ExpectedPostconditions:
        host = str(parameters.get("target_host", "")).strip()
        vuln = str(parameters.get("vulnerability_id", "")).strip()
        updates: Dict[str, Any] = {
            "exploitation": {
                "compromised_hosts": {host: {"via": vuln}},
            }
        }
        logger.debug(
            "ExploitAttempt expected postconditions host='%s' vuln='%s': %s",
            host,
            vuln,
            updates,
        )
        return ExpectedPostconditions(
            phase_transition="PRIVILEGE_ESCALATION",
            state_updates=updates,
        )


class PrivilegeEscalation(ActionDefinition):
    """Simulated privilege escalation on a compromised host.

    Parameters:
    - target_host: str
    """

    def __init__(self) -> None:
        super().__init__(
            name="PrivilegeEscalation",
            description=(
                "Attempt to escalate privileges on a compromised host in a "
                "simulated manner."
            ),
            allowed_phases=["PRIVILEGE_ESCALATION"],
            required_parameters=["target_host"],
        )

    def validate_preconditions(
        self, state: AttackStateLike, parameters: Mapping[str, Any]
    ) -> tuple[bool, str]:
        ok, reason = self._validate_common(state, parameters)
        if not ok:
            return ok, reason

        host = parameters.get("target_host")
        if not isinstance(host, str) or not host:
            logger.info(
                "Invalid 'target_host' for PrivilegeEscalation: %r", host
            )
            return False, "Parameter 'target_host' must be a non-empty string"

        return True, "OK"

    def expected_postconditions(
        self, state: AttackStateLike, parameters: Mapping[str, Any]
    ) -> ExpectedPostconditions:
        host = str(parameters.get("target_host", "")).strip()
        updates: Dict[str, Any] = {
            "privilege_escalation": {
                host: {"privilege": "root"}
            }
        }
        logger.debug(
            "PrivilegeEscalation expected postconditions for '%s': %s", host, updates
        )
        return ExpectedPostconditions(
            phase_transition="PROOF_OF_COMPROMISE",
            state_updates=updates,
        )


class ProofOfCompromise(ActionDefinition):
    """Simulated proof-of-compromise generation.

    Parameters:
    - evidence_tag: str
    """

    def __init__(self) -> None:
        super().__init__(
            name="ProofOfCompromise",
            description=(
                "Generate a simulated proof artifact indicating successful "
                "compromise, without extracting real data."
            ),
            allowed_phases=["PROOF_OF_COMPROMISE"],
            required_parameters=["evidence_tag"],
        )

    def validate_preconditions(
        self, state: AttackStateLike, parameters: Mapping[str, Any]
    ) -> tuple[bool, str]:
        ok, reason = self._validate_common(state, parameters)
        if not ok:
            return ok, reason

        tag = parameters.get("evidence_tag")
        if not isinstance(tag, str) or not tag:
            logger.info(
                "Invalid 'evidence_tag' for ProofOfCompromise: %r", tag
            )
            return False, "Parameter 'evidence_tag' must be a non-empty string"

        return True, "OK"

    def expected_postconditions(
        self, state: AttackStateLike, parameters: Mapping[str, Any]
    ) -> ExpectedPostconditions:
        tag = str(parameters.get("evidence_tag", "")).strip()
        updates: Dict[str, Any] = {
            "proof": {
                "artifacts": [
                    {
                        "type": "marker",
                        "tag": tag,
                        "details": "simulated-proof",
                    }
                ]
            }
        }
        logger.debug(
            "ProofOfCompromise expected postconditions tag='%s': %s", tag, updates
        )
        return ExpectedPostconditions(
            phase_transition="COMPLETED",
            state_updates=updates,
        )


# -------------
# Static Registry
# -------------

_REGISTRY: Dict[str, ActionDefinition] = {
    "PassiveRecon": PassiveRecon(),
    "ServiceEnumeration": ServiceEnumeration(),
    "ExploitAttempt": ExploitAttempt(),
    "PrivilegeEscalation": PrivilegeEscalation(),
    "ProofOfCompromise": ProofOfCompromise(),
}


def list_actions() -> list[str]:
    """Return the list of registered action names (sorted for determinism)."""
    names = sorted(_REGISTRY.keys())
    logger.debug("Listing actions: %s", names)
    return names


def get_action_definition(name: str) -> Optional[ActionDefinition]:
    """Return the action definition by name if registered."""
    if not isinstance(name, str):
        logger.warning("Action name must be a string: %r", name)
        return None
    definition = _REGISTRY.get(name)
    if definition is None:
        logger.info("Requested unknown action definition: '%s'", name)
    else:
        logger.debug("Fetched action definition for '%s'", name)
    return definition


def validate_action(
    name: str, state: AttackStateLike, parameters: Mapping[str, Any]
) -> tuple[bool, str]:
    """Validate an action proposal deterministically against its definition.

    This does NOT perform policy checks. The Policy Engine should consider
    multi-step ordering rules. This function only validates local preconditions
    and parameter integrity for a single action.
    """
    definition = get_action_definition(name)
    if definition is None:
        return False, "Unknown action"

    ok, reason = definition.validate_preconditions(state, parameters)
    logger.debug(
        "Validation for action '%s' returned ok=%s reason='%s'",
        name,
        ok,
        reason,
    )
    return ok, reason


__all__ = [
    "ActionDefinition",
    "ExpectedPostconditions",
    "PassiveRecon",
    "ServiceEnumeration",
    "ExploitAttempt",
    "PrivilegeEscalation",
    "ProofOfCompromise",
    "list_actions",
    "get_action_definition",
    "validate_action",
]
