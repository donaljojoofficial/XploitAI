"""
AI Advisor — Integration and Auditing Layer

Responsibilities:
- Act as a bridge between the AI decision engine and the policy engine.
- Create a deterministic, structured audit trail for every AI decision evaluated.
- Encapsulate the logic of "propose -> validate -> log".

Why this exists:
The Orchestrator needs to know if an AI's proposed action is valid. Instead of
calling the policy engine directly, it can use this advisor. The advisor
guarantees that every validation check is logged for security, debugging, and
explainability purposes, fulfilling the requirements of a robust audit trail.
"""
from __future__ import annotations

import datetime
import json
import logging
from typing import TYPE_CHECKING, Any, Dict

# Use TYPE_CHECKING to avoid circular imports at runtime while allowing type hints.
# The calling code (e.g., Orchestrator) is responsible for providing concrete instances.
if TYPE_CHECKING:
    from agent.decision import ActionProposal
    from policy.engine import PolicyEngine, PolicyDecision, AttackStateLike

# Dedicated logger for the AI audit trail.
# This allows routing audit logs to a separate file or system if needed.
audit_logger = logging.getLogger("ai_audit")


class AIAdvisor:
    """
    Integrates AI proposals with policy validation and creates an audit trail.
    """

    def __init__(self, *, policy_engine: "PolicyEngine"):
        """Initializes the advisor with a policy engine instance."""
        if not hasattr(policy_engine, "validate"):
            raise TypeError("AIAdvisor requires a valid PolicyEngine instance.")
        self.policy_engine = policy_engine

    def validate_and_log(
        self, *, proposal: "ActionProposal", state: "AttackStateLike"
    ) -> "PolicyDecision":
        """
        Validates a single AI proposal against the policy engine and logs the
        interaction as a structured audit record.

        Args:
            proposal: The AI-generated action proposal to validate.
            state: The current attack state against which to validate.

        Returns:
            The `PolicyDecision` object returned by the policy engine.
        """
        # 1. Perform validation by calling the policy engine.
        policy_decision = self.policy_engine.validate(
            name=proposal.name, state=state, parameters=proposal.parameters
        )

        # 2. Create a structured, JSON-serializable audit record.
        audit_record: Dict[str, Any] = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "decision_source": "ai_agent",
            "state_summary": {"phase": state.current_phase},
            "ai_proposal": {
                "action_name": proposal.name,
                "parameters": dict(proposal.parameters),
                "rationale": proposal.description,
            },
            "policy_evaluation": {
                "approved": policy_decision.allowed,
                "reason": policy_decision.reason,
            },
        }

        # 3. Log the record for auditing and analysis.
        audit_logger.info("AI_DECISION_AUDIT %s", json.dumps(audit_record, default=str))

        return policy_decision