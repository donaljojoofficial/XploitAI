"""
AI Advisor - Integration and Auditing Layer.

Responsibilities:
- Act as a bridge between the AI decision engine and the policy engine.
- Create a deterministic, structured audit trail for every AI decision evaluated.
- Encapsulate the logic of "propose -> validate -> log".

Why this exists:
The orchestrator needs to know whether an AI-proposed action is valid. Instead
of calling the policy engine directly, it can use this advisor. The advisor
guarantees that every validation check is logged for security, debugging, and
explainability.
"""
from __future__ import annotations

import datetime
import json
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent.decision import ActionProposal
    from policy.engine import AttackStateLike, PolicyDecision, PolicyEngine


audit_logger = logging.getLogger("ai_audit")


class AIAdvisor:
    """Integrates AI proposals with policy validation and audit logging."""

    def __init__(self, *, policy_engine: "PolicyEngine"):
        if not hasattr(policy_engine, "validate"):
            raise TypeError("AIAdvisor requires a valid PolicyEngine instance.")
        self.policy_engine = policy_engine

    def validate_and_log(
        self, *, proposal: "ActionProposal", state: "AttackStateLike"
    ) -> "PolicyDecision":
        """Validate an AI proposal against policy and emit an audit record."""
        policy_decision = self.policy_engine.validate(
            name=proposal.name,
            state=state,
            parameters=proposal.parameters,
        )

        audit_record: dict[str, Any] = {
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

        audit_logger.info("AI_DECISION_AUDIT %s", json.dumps(audit_record, default=str))
        return policy_decision
