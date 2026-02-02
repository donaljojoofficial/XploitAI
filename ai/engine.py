"""
Concrete implementation of the AI Decision Engine.
"""
from __future__ import annotations

import logging
from typing import Any, Mapping, Optional

from actions import predefined
from .schemas import Decision, DecisionRequest

logger = logging.getLogger(__name__)


class RuleBasedDecisionEngine:
    """
    A simple, deterministic, rule-based AI decision engine for Phase 1.

    This engine uses a series of heuristics based on the current attack phase
    to recommend the next action. It is designed to be safe, predictable, and
    conservative, selecting actions only from the globally available action registry.

    This class is a concrete implementation of the DecisionEngine protocol.
    """

    def evaluate(
        self, request: DecisionRequest, context: Optional[Mapping[str, Any]] = None
    ) -> Decision:
        """
        Evaluates the current state and recommends a single action based on
        pre-defined rules for the current attack phase.
        """
        phase = request.decision_input.phase
        past_action_types = {
            action.action_type for action in request.decision_input.past_actions
        }
        known_actions = predefined.list_actions()

        logger.info(
            "Evaluating decision for phase '%s' with past actions: %s",
            phase,
            past_action_types,
        )

        # --- Phase-based Decision Logic ---

        if phase == "RECONNAISSANCE":
            # Use the correct action 'PassiveRecon' from the action registry.
            if "PassiveRecon" in known_actions and "PassiveRecon" not in past_action_types:
                logger.debug("Rule matched: Proposing 'PassiveRecon' action.")
                return Decision(
                    action_type="PassiveRecon",
                    # Per actions/predefined.py, PassiveRecon requires 'target_domain'.
                    # The DecisionInput schema does not yet provide this, so a
                    # placeholder is used for this initial implementation.
                    parameters={"target_domain": "example.com"},
                    rationale="Initial reconnaissance phase. Starting with passive reconnaissance.",
                )

        # --- Fallback Action ---
        # If no specific rule matches, we cannot make a decision. The 'wait'
        # action is not in the registry, so we default to a safe 'no_op'.
        logger.warning(
            "Could not determine a valid action. No rules matched for phase '%s'.", phase
        )
        # This action will likely be rejected by the policy engine, which is the
        # desired safe behavior.
        return Decision(
            action_type="no_op",
            parameters={},
            rationale="CRITICAL: No decision rule matched for the current state. The system cannot proceed.",
        )