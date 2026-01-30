"""
Simulation Executor — XploitAI (Phase 1)

Responsibilities (per architecture.md):
- Simulation-only executor
- Produces mock outcomes
- Updates attack state deterministically

Non-Responsibilities:
- No external command execution
- No network or system calls
- No AI reasoning

Usage contract (Phase 1):
- Executor is invoked AFTER policy approval.
- Caller must supply the Action to execute and the ExpectedPostconditions
  provided by the Policy Engine. The executor will apply the state updates and
  optional phase transition described therein and persist an ActionResult.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping, Optional

from django.db import transaction

from actions.predefined import ExpectedPostconditions
from core.models import Action, ActionResult

logger = logging.getLogger(__name__)


class SimulationExecutor:
    """Deterministic, side-effect-free (external) simulation executor.

    This executor mutates only the application state (database) by updating the
    AttackState per the expected postconditions and persisting an ActionResult.
    It assumes that the provided action has been approved by the Policy Engine.
    """

    def execute(
        self,
        *,
        action: Action,
        expected: ExpectedPostconditions,
    ) -> ActionResult:
        """Execute an approved action by applying expected postconditions.

        Parameters:
        - action: The Action ORM instance to execute.
        - expected: ExpectedPostconditions produced by the Policy Engine for
          this action and its parameters.

        Returns: The persisted ActionResult instance.
        """
        self._validate_inputs(action, expected)

        with transaction.atomic():
            # Apply deterministic state changes
            state = action.attack_state

            # Shallow merge of top-level keys per coding standards (explicit)
            updates: Mapping[str, Any] = expected.state_updates or {}
            if updates:
                logger.debug(
                    "Executor applying state updates for action '%s': %s",
                    action.name,
                    updates,
                )
                state.update_state_data(dict(updates))

            # Phase transition if requested
            if expected.phase_transition and expected.phase_transition != state.current_phase:
                logger.debug(
                    "Executor advancing phase for action '%s': %s -> %s",
                    action.name,
                    state.current_phase,
                    expected.phase_transition,
                )
                state.advance_phase(expected.phase_transition)

            # Create ActionResult (success)
            result = ActionResult.objects.create(
                action=action,
                success=True,
                output={
                    "applied_updates": dict(updates),
                    "phase_transition": expected.phase_transition,
                },
                log_message=self._build_success_log(action, expected),
            )

            # Update Action status to EXECUTED
            action.status = "EXECUTED"
            action.save(update_fields=["status"])

        logger.info(
            "Executed action '%s' with result id=%s", action.name, result.id
        )
        return result

    # -------------------
    # Internal helpers
    # -------------------

    def _validate_inputs(self, action: Any, expected: Any) -> None:
        if not isinstance(action, Action):
            logger.error("Executor received invalid action: %r", action)
            raise TypeError("'action' must be an instance of core.models.Action")
        if not isinstance(expected, ExpectedPostconditions):
            logger.error("Executor received invalid expected postconditions: %r", expected)
            raise TypeError(
                "'expected' must be an instance of actions.predefined.ExpectedPostconditions"
            )

    def _build_success_log(
        self, action: Action, expected: ExpectedPostconditions
    ) -> str:
        parts = [
            f"Action '{action.name}' executed in phase {action.attack_state.current_phase}.",
        ]
        if expected.state_updates:
            parts.append("Applied state updates.")
        if expected.phase_transition:
            parts.append(
                f"Transitioned phase to {expected.phase_transition}."
            )
        return " " .join(parts)


__all__ = ["SimulationExecutor"]
