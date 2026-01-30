"""
Orchestration Loop (State Machine) — XploitAI (Phase 1)

Responsibilities (per architecture.md):
- Lives in core/ as part of orchestration and state machine
- Coordinates the flow: Agent → Policy → Action Registry → Executor → State Update
- Deterministically advances the simulation using database-backed state

Non-Responsibilities:
- No direct execution of real commands
- No policy bypass
- No AI reasoning beyond calling the Decision Engine interface

Design:
- The orchestrator executes one action per step.
- For each step, it asks the Decision Engine for proposals, validates via Policy
  Engine, executes the first approved action via the Simulation Executor, and
  updates the AttackState.
- Rejections are recorded by setting Action.status to REJECTED.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from django.db import transaction

from agent.decision import DecisionEngine, ActionProposal
from core.models import Action, AttackState
from executor.simulator import SimulationExecutor
from policy.engine import PolicyEngine

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class OrchestrationStepResult:
    """Outcome of a single orchestration step."""

    performed: bool
    finished: bool
    message: str
    action: Optional[Action] = None


class Orchestrator:
    """Deterministic orchestration engine for the attack simulation."""

    def __init__(
        self,
        *,
        decision_engine: Optional[DecisionEngine] = None,
        policy_engine: Optional[PolicyEngine] = None,
        executor: Optional[SimulationExecutor] = None,
    ) -> None:
        self.decision_engine = decision_engine or DecisionEngine()
        self.policy_engine = policy_engine or PolicyEngine()
        self.executor = executor or SimulationExecutor()

    def step(self, *, state: AttackState) -> OrchestrationStepResult:
        """Execute a single orchestration step for the given AttackState.

        Returns an OrchestrationStepResult describing what happened.
        """
        if state.current_phase == "COMPLETED":
            logger.info("Orchestration halted: state is already COMPLETED")
            return OrchestrationStepResult(
                performed=False,
                finished=True,
                message="Already completed",
                action=None,
            )

        proposals = self.decision_engine.propose_next_actions(state, limit=3)
        if not proposals:
            logger.info("No proposals available; orchestration cannot proceed")
            return OrchestrationStepResult(
                performed=False,
                finished=True,
                message="No proposals available",
                action=None,
            )

        # Try proposals in order until one is approved by policy
        for proposal in proposals:
            action = self._create_pending_action(state, proposal)
            decision = self.policy_engine.validate(
                action.name, state, action.parameters
            )

            if not decision.allowed:
                logger.info(
                    "Policy rejected action '%s': %s", action.name, decision.reason
                )
                self._mark_rejected(action)
                continue

            logger.debug(
                "Policy approved action '%s'; executing with expected postconditions",
                action.name,
            )

            # Execute within a transaction to ensure atomicity around state change
            with transaction.atomic():
                result = self.executor.execute(action=action, expected=decision.expected)  # type: ignore[arg-type]
                logger.debug("ActionResult persisted id=%s", result.id)

            # Refresh state to observe any phase transition
            state.refresh_from_db()
            finished = state.current_phase == "COMPLETED"
            msg = "Executed action successfully"
            logger.info(
                "Step completed with action '%s'; finished=%s",
                action.name,
                finished,
            )
            return OrchestrationStepResult(
                performed=True,
                finished=finished,
                message=msg,
                action=action,
            )

        logger.info("All proposals rejected by policy; halting this cycle")
        return OrchestrationStepResult(
            performed=False,
            finished=True,
            message="All proposals rejected by policy",
            action=None,
        )

    def run_until_complete(self, *, state: AttackState, max_steps: int = 20) -> int:
        """Run orchestration steps until completion or until max_steps reached.

        Returns the number of actions executed.
        """
        executed = 0
        for _ in range(max_steps):
            result = self.step(state=state)
            if not result.performed:
                break
            executed += 1
            if result.finished:
                break
        logger.info("run_until_complete finished after %s executed steps", executed)
        return executed

    # -------------------
    # Internal helpers
    # -------------------

    def _create_pending_action(self, state: AttackState, proposal: ActionProposal) -> Action:
        action = Action.objects.create(
            attack_state=state,
            name=proposal.name,
            description=proposal.description,
            parameters=dict(proposal.parameters),
            status="PENDING",
        )
        logger.debug("Created PENDING action id=%s name=%s", action.id, action.name)
        return action

    def _mark_rejected(self, action: Action) -> None:
        action.status = "REJECTED"
        action.save(update_fields=["status"])
        logger.debug("Marked action id=%s as REJECTED", action.id)


__all__ = [
    "Orchestrator",
    "OrchestrationStepResult",
]
