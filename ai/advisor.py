"""
AI Advisor: The integration layer between AI decisions and policy validation.
"""
from __future__ import annotations

import logging
from typing import Optional

from actions.predefined import AttackStateLike
from policy.engine import PolicyEngine
from .engine import RuleBasedDecisionEngine
from .llm.base import BaseLLMAdapter
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
        llm_adapter: Optional[BaseLLMAdapter] = None,
    ) -> None:
        self.decision_engine = decision_engine or RuleBasedDecisionEngine()
        self.policy_engine = policy_engine or PolicyEngine()
        self.llm_adapter = llm_adapter
        logger.info("AIAdvisor initialized.")

    def get_validated_decision(
        self, *, request: DecisionRequest, state: AttackStateLike
    ) -> ValidatedDecision:
        """
        Generates and validates a single AI-recommended action with fallback logic.

        This method orchestrates the flow:
        1. Attempts to get a recommendation from the LLM adapter (if configured).
        2. Falls back to the Rule-Based Decision Engine if the LLM is unavailable,
           fails, or returns None.
        3. Passes the proposed action to the policy engine for validation, using
           the authoritative `AttackStateLike` object.
        4. Returns a composite object with both the AI's proposal and the
           policy's verdict.

        Note: This method requires both `request` and `state` because the
        `StateAdapter` (which will derive `request` from `state`) is not yet
        fully implemented.
        """
        ai_decision = None

        # 1. Try LLM Adapter (Advisory Layer)
        if self.llm_adapter:
            try:
                logger.debug("Requesting recommendation from LLM adapter.")
                # Assuming request is compatible with DecisionInput schema
                ai_decision = self.llm_adapter.get_recommendation(request)  # type: ignore
                if ai_decision:
                    logger.info("Using LLM-generated recommendation.")
            except Exception as e:
                logger.warning(f"LLM adapter failed: {e}. Falling back to rules.")
                ai_decision = None

        # 2. Fallback to Rule-Based Engine
        if not ai_decision:
            logger.debug("Getting decision from Rule-Based AI engine.")
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

        if policy_verdict.approval_required:
            logger.info(
                "AUDIT: Action '%s' requires approval. Pending human authorization.",
                ai_decision.action_type,
            )

        result = ValidatedDecision(
            ai_decision=ai_decision, policy_decision=policy_verdict
        )

        return result