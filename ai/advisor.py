"""
AI Advisor: The integration layer between AI decisions and policy validation.
"""
from __future__ import annotations

import logging
from typing import Optional

from actions.predefined import AttackStateLike
from policy.engine import PolicyEngine
from .engine import RuleBasedDecisionEngine
from .schemas import DecisionRequest, ValidatedDecision

logger = logging.getLogger(__name__)


class AIAdvisor:
    """
    Coordinates between the AI Decision Engine and the Policy Engine.

    This component takes a state representation, gets a decision from the AI,
    and validates that decision against the system's policies. It acts as a
    bridge, ensuring AI recommendations are always checked before being
    considered for execution. This fulfills the architectural requirement that
    the AI is advisory and policy is authoritative.
    """

    def __init__(
        self,
        decision_engine: Optional[RuleBasedDecisionEngine] = None,
        policy_engine: Optional[PolicyEngine] = None,
    ) -> None:
        self.decision_engine = decision_engine or RuleBasedDecisionEngine()
        self.policy_engine = policy_engine or PolicyEngine()
        logger.info("AIAdvisor initialized.")

    def get_validated_decision(
        self, *, request: DecisionRequest, state: AttackStateLike
    ) -> ValidatedDecision:
        """
        Generates and validates a single AI-recommended action.

        This method orchestrates the flow:
        1. Gets a decision from the AI engine based on the `DecisionRequest`.
        2. Passes the proposed action to the policy engine for validation, using
           the authoritative `AttackStateLike` object.
        3. Returns a composite object with both the AI's proposal and the
           policy's verdict.

        Note: This method requires both `request` and `state` because the
        `StateAdapter` (which will derive `request` from `state`) is not yet
        fully implemented.
        """
        logger.debug("Getting decision from AI engine.")
        ai_decision = self.decision_engine.evaluate(request)

        logger.debug(
            "Validating AI decision for action '%s' with policy engine.",
            ai_decision.action_type,
        )
        # The policy engine is the source of truth for validation.
        policy_verdict = self.policy_engine.validate(
            name=ai_decision.action_type,
            state=state,
            parameters=ai_decision.parameters,
        )

        result = ValidatedDecision(
            ai_decision=ai_decision, policy_decision=policy_verdict
        )

        return result