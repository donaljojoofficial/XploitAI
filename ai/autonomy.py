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

from core.models import Action, AttackState, ExecutionTask, DefenderAlert
# Use the concrete implementation from agent.decision
from agent.decision import DecisionEngine
from policy.engine import PolicyEngine

logger = logging.getLogger(__name__)


class AutonomousController:
    """
    Controller for the autonomous AI execution loop.

    This class acts as the central nervous system for the autonomous mode.
    It does not make decisions itself but coordinates the components that do.
    """

    def __init__(
        self,
        attack_state_id: int,
        max_steps: int = 50,
        max_consecutive_failures: int = 3
    ) -> None:
        self.attack_state_id = attack_state_id
        self.running = False
        self.max_steps = max_steps
        self.max_consecutive_failures = max_consecutive_failures
        self.step_count = 0

        # Initialize components
        self.decision_engine = DecisionEngine()
        self.policy_engine = PolicyEngine()

    def start(self) -> None:
        """Start the autonomous control loop."""
        self.running = True
        self.step_count = 0
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
        2. Sync execution status from tasks to actions.
        3. Check stop conditions (max steps, failures).
        4. Check for pending tasks (wait if busy).
        5. Get AI decision.
        6. Validate with Policy.
        7. Queue ExecutionTask.

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

        # 1. Sync Action states with ExecutionTasks
        self._sync_action_states(state)

        # 2. Check Stop Conditions
        if self._check_stop_conditions(state):
            self.stop()
            return False

        # 3. Wait for execution results
        if self._has_pending_tasks():
            logger.debug("Pending tasks detected. Waiting for execution.")
            return False

        # 4. Get AI Decision
        # We request 1 proposal for the autonomous loop
        proposals = self.decision_engine.propose_next_actions(state, limit=1)
        if not proposals:
            logger.info("Decision Engine returned no proposals. Goal reached or stuck. Stopping.")
            self.stop()
            return False

        proposal = proposals[0]

        # 5. Policy Validation
        policy_decision = self.policy_engine.validate(
            proposal.name, state, proposal.parameters
        )

        if not policy_decision.allowed:
            logger.warning(
                "Policy rejected action '%s': %s", proposal.name, policy_decision.reason
            )
            # TODO: Feed rejection back to AI memory (Phase 3)
            return False

        # 6. Queue Execution Task
        self._queue_execution(state, proposal, policy_decision)
        self.step_count += 1
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

    def _sync_action_states(self, state: AttackState) -> None:
        """
        Update Action records based on ExecutionTask results.
        This closes the loop between Executor and AI Memory.
        """
        pending_actions = Action.objects.filter(attack_state=state, status='PENDING')
        for action in pending_actions:
            # Find the task linked to this action
            # Note: parameters is a JSONField
            task = ExecutionTask.objects.filter(
                parameters__contains={'_action_id': action.id}
            ).first()

            if task and task.status in ['COMPLETED', 'FAILED']:
                action.status = task.status
                action.save(update_fields=['status'])
                logger.debug("Synced Action %s status to %s", action.id, task.status)

    def _check_stop_conditions(self, state: AttackState) -> bool:
        """
        Check if the autonomous loop should stop.
        """
        # 1. Max Steps
        if self.step_count >= self.max_steps:
            logger.info("STOP CONDITION: Max steps (%d) reached.", self.max_steps)
            return True

        # 2. Defender Alerts
        # Stop if the defender has detected critical activity.
        if DefenderAlert.objects.filter(
            attack_state=state,
            severity__in=['HIGH', 'CRITICAL']
        ).exists():
            logger.warning("STOP CONDITION: Critical Defender Alert detected.")
            return True

        # 2. Consecutive Failures
        # Check the last N actions
        recent_actions = Action.objects.filter(
            attack_state=state
        ).order_by('-created_at')[:self.max_consecutive_failures]

        if len(recent_actions) >= self.max_consecutive_failures:
            if all(a.status == 'FAILED' for a in recent_actions):
                logger.warning(
                    "STOP CONDITION: %d consecutive failures detected.",
                    self.max_consecutive_failures
                )
                return True

        return False

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
