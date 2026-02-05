"""
Autonomous AI Control Loop — XploitAI

Responsibilities:
- Orchestrate the AI decision -> policy -> execution cycle.
- Manage the autonomous loop state (start/stop).
- Interface with the ExecutionTask queue.

This module implements the high-level control logic that drives the
autonomous behavior of the system in Phase 2.
"""

from __future__ import annotations

import logging
from typing import Optional

from django.db import transaction

from core.models import Action, AttackState, ExecutionTask
# Assuming the existence of these modules based on architecture.md
from ai.decision_engine import DecisionEngine
from policy.engine import PolicyEngine

logger = logging.getLogger(__name__)


class AutonomousController:
    """
    Controller for the autonomous AI execution loop.

    This class acts as the central nervous system for the autonomous mode.
    It does not make decisions itself but coordinates the components that do.
    """

    def __init__(self, attack_state_id: int) -> None:
        self.attack_state_id = attack_state_id
        self.running = False

        # Initialize components
        # In a real implementation, these might be injected or configured
        self.decision_engine = DecisionEngine()
        self.policy_engine = PolicyEngine()

    def start(self) -> None:
        """Start the autonomous control loop."""
        self.running = True
        logger.info("AutonomousController started for AttackState ID %s", self.attack_state_id)

    def stop(self) -> None:
        """Stop the autonomous control loop."""
        self.running = False
        logger.info("AutonomousController stopped for AttackState ID %s", self.attack_state_id)

    def run_cycle(self) -> bool:
        """
        Execute a single step of the autonomous loop.

        Flow:
        1. Check if running.
        2. Check for pending tasks (wait if busy).
        3. Get AI decision.
        4. Validate with Policy.
        5. Queue ExecutionTask.

        Returns:
            bool: True if a task was queued, False otherwise (waiting or stopped).
        """
        if not self.running:
            return False

        try:
            state = AttackState.objects.get(id=self.attack_state_id)
        except AttackState.DoesNotExist:
            logger.error("AttackState %s not found. Stopping controller.", self.attack_state_id)
            self.stop()
            return False

        # 1. Wait for execution results
        if self._has_pending_tasks():
            logger.debug("Pending tasks detected. Waiting for execution.")
            return False

        # 2. Get AI Decision
        # We request 1 proposal for the autonomous loop
        proposals = self.decision_engine.propose_next_actions(state, limit=1)
        if not proposals:
            logger.info("Decision Engine returned no proposals. Idle.")
            return False

        proposal = proposals[0]

        # 3. Policy Validation
        policy_decision = self.policy_engine.validate(
            proposal.name, state, proposal.parameters
        )

        if not policy_decision.allowed:
            logger.warning(
                "Policy rejected action '%s': %s", proposal.name, policy_decision.reason
            )
            # TODO: Feed rejection back to AI memory (Phase 3)
            return False

        # 4. Queue Execution Task
        self._queue_execution(state, proposal, policy_decision)
        return True

    def _has_pending_tasks(self) -> bool:
        """
        Check if there are pending execution tasks.

        Note: Since ExecutionTask currently lacks a direct link to AttackState,
        this checks for ANY pending task. In a multi-tenant system, this
        would need to be scoped to the specific attack simulation.
        """
        return ExecutionTask.objects.filter(
            status__in=['PENDING', 'RUNNING']
        ).exists()

    def _queue_execution(self, state: AttackState, proposal, policy_decision) -> None:
        """
        Persist the decision as an Action and queue it for execution.
        """
        with transaction.atomic():
            # 1. Create the Action record (for history/audit)
            action = Action.objects.create(
                attack_state=state,
                name=proposal.name,
                description=proposal.description,
                parameters=proposal.parameters,
                status='PENDING'
            )

            # 2. Create the ExecutionTask (for the executor)
            # We inject the action_id so the executor can link the result back
            task_params = proposal.parameters.copy()
            task_params['_action_id'] = action.id

            ExecutionTask.objects.create(
                action_name=proposal.name,
                parameters=task_params,
                status='PENDING',
                requires_approval=False,  # Future: Check policy_decision.requires_approval
            )

            logger.info(
                "Queued action '%s' (Action ID: %s) for execution.",
                proposal.name,
                action.id
            )
