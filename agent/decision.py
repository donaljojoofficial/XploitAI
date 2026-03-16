"""
AI Decision Engine Interface — XploitAI (Phase 1)

Responsibilities (per architecture.md):
- Live in agent/ layer
- Provide reasoning and action ranking interface
- Propose next actions only (no execution, no policy bypass)

Non-Responsibilities:
- No execution logic
- No direct state mutation
- No network/system calls; no external LLM calls in Phase 1 implementation

Design:
- Deterministic, heuristic-based action proposal reflective of current state.
- Uses the Action Registry to validate local preconditions so proposals are
  well-formed before sending to the Policy Engine.
- Produces a ranked list of ActionProposal objects for the orchestration layer
  to persist as Action models and pass through Policy and Executor.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, MutableMapping, Optional, Protocol

from actions.predefined import validate_action
from ai.llm.gemini import GeminiAdapter
from ai.schemas import DecisionInput, KnownService, PastActionSummary, DecisionRequest, ActionResultSummary

logger = logging.getLogger(__name__)


class AttackStateLike(Protocol):
    """Minimal interface required from the core AttackState.

    The decision engine remains decoupled from Django ORM. The orchestration
    layer will pass a concrete instance implementing these attributes.
    """

    current_phase: str
    state_data: MutableMapping[str, Any]


@dataclass(frozen=True)
class ActionProposal:
    """Represents a candidate action proposed by the decision engine."""

    name: str
    description: str
    parameters: Mapping[str, Any]
    score: float


class DecisionEngine:
    """Hybrid AI decision engine (Phase 1+ interface).

    Provides propose_next_actions which returns a ranked list of action
    proposals based on the current state. The ranking is deterministic and
    relies on simple heuristics aligned with the kill chain.

    Now includes a Hybrid mode:
    1. Attempt Gemini LLM decision.
    2. Fallback to deterministic heuristics if LLM fails or is invalid.
    """

    def __init__(self) -> None:
        from core.config import get_config
        provider = get_config("DEFAULT_LLM_PROVIDER", "gemini")
        
        if provider == "ollama":
            from ai.llm.ollama_adapter import OllamaAdapter
            self.llm_adapter = OllamaAdapter()
        elif provider == "claude":
            from ai.llm.anthropic import AnthropicAdapter
            self.llm_adapter = AnthropicAdapter()
        elif provider == "groq":
            from ai.llm.groq_adapter import GroqAdapter
            self.llm_adapter = GroqAdapter()
        else:
            self.llm_adapter = GeminiAdapter()

    def generate_actions(self, state: AttackStateLike, limit: int = 3) -> list[ActionProposal]:
        """Alias for propose_next_actions to satisfy AutonomousController interface."""
        return self.propose_next_actions(state, limit)

    def propose_next_actions(
        self, state: AttackStateLike, limit: int = 3
    ) -> list[ActionProposal]:
        if state is None:
            logger.warning("DecisionEngine received None state")
            return []
        if limit <= 0:
            logger.info("DecisionEngine called with non-positive limit: %s", limit)
            return []

        phase = state.current_phase
        logger.info("Proposing next actions for phase: %s", phase)

        # --- HYBRID AI ATTEMPT ---
        ai_proposal = self._attempt_ai_decision(state)
        if ai_proposal:
            logger.info("DecisionEngine: using Gemini LLM output")
            return [ai_proposal]

        logger.info("DecisionEngine: falling back to deterministic logic")
        # -------------------------

        candidates: list[ActionProposal] = []

        if phase == "RECONNAISSANCE":
            prop = self._propose_passive_recon(state)
            if prop:
                candidates.append(prop)
        elif phase == "ENUMERATION":
            prop = self._propose_service_enumeration(state)
            if prop:
                candidates.append(prop)
        elif phase == "EXPLOITATION":
            prop = self._propose_exploit_attempt(state)
            if prop:
                candidates.append(prop)
        elif phase == "PRIVILEGE_ESCALATION":
            prop = self._propose_privilege_escalation(state)
            if prop:
                candidates.append(prop)
        elif phase == "PROOF_OF_COMPROMISE":
            prop = self._propose_proof_of_compromise(state)
            if prop:
                candidates.append(prop)
        else:
            # COMPLETED or unknown phase -> no proposals
            logger.info("No proposals for phase: %s", phase)

        # Validate against action registry's local preconditions for determinism
        valid_candidates: list[ActionProposal] = []
        for c in candidates:
            ok, reason = validate_action(c.name, state, c.parameters)
            if ok:
                valid_candidates.append(c)
            else:
                logger.info(
                    "Discarding proposal '%s' due to preconditions: %s", c.name, reason
                )

        # Deterministic ranking: by score desc, then by name asc
        valid_candidates.sort(key=lambda p: (-p.score, p.name))
        return valid_candidates[:limit]

    # -------------------
    # Internal helpers
    # -------------------

    def _attempt_ai_decision(self, state: AttackStateLike) -> Optional[ActionProposal]:
        """Attempts to generate a valid action proposal using the LLM adapter."""
        try:
            decision_input = self._build_decision_input(state)
            
            # Pass planner context via DecisionRequest
            context = state.state_data.get('planner_context') if state.state_data else None
            request = DecisionRequest(decision_input=decision_input, context=context)
            
            decision = self.llm_adapter.get_recommendation(request)

            if not decision:
                return None

            # Validate that the action exists and preconditions are met locally
            ok, reason = validate_action(decision.action_type, state, decision.parameters)
            if not ok:
                logger.warning(
                    "Gemini proposed invalid action '%s': %s", decision.action_type, reason
                )
                return None

            return ActionProposal(
                name=decision.action_type,
                description=decision.rationale or "AI generated decision",
                parameters=decision.parameters,
                score=1.0,
            )
        except Exception as e:
            logger.error("Error during AI decision attempt: %s", e)
            return None

    def _build_decision_input(self, state: AttackStateLike) -> DecisionInput:
        """Constructs the AI input schema from the current attack state."""
        data = state.state_data or {}
        
        # Best-effort extraction of known services for context
        known_services = []
        # (Future: Extract services from data['enumeration']['services'] if available)
        
        # Extract history from state_data (populated by AutonomousController)
        past_actions = []
        raw_history = data.get('execution_history', [])
        
        for item in raw_history:
            past_actions.append(PastActionSummary(
                action_type=item.get('action', 'Unknown'),
                parameters=item.get('parameters', {}),
                phase=None,
                timestamp=item.get('timestamp')
            ))

        last_result = None
        if raw_history:
            last_item = raw_history[-1]
            success = (last_item.get('status') == 'COMPLETED')
            output_text = last_item.get('result', '')
            
            last_result = ActionResultSummary(
                success=success,
                output_summary=output_text if success else None,
                error=output_text if not success else None
            )

        return DecisionInput(
            phase=state.current_phase,
            known_services=known_services,
            past_actions=past_actions,
            last_result=last_result,
        )

    def _propose_passive_recon(self, state: AttackStateLike) -> Optional[ActionProposal]:
        data = state.state_data or {}
        target_domain = None
        # Prefer explicit target domain keys from state
        if isinstance(data.get("target_domain"), str) and data.get("target_domain"):
            target_domain = data["target_domain"]
        elif isinstance(data.get("target"), dict) and isinstance(
            data.get("target", {}).get("domain"), str
        ) and data.get("target", {}).get("domain"):
            target_domain = data.get("target", {}).get("domain")

        if not target_domain:
            logger.debug("No target domain found for PassiveRecon proposal")
            return None

        params = {"target_domain": target_domain}
        return ActionProposal(
            name="PassiveRecon",
            description="Collect publicly available information about the target domain.",
            parameters=params,
            score=1.0,
        )

    def _propose_service_enumeration(self, state: AttackStateLike) -> Optional[ActionProposal]:
        data = state.state_data or {}
        
        # Try planner context first (Phase 2 standard)
        planner_ctx = data.get('planner_context', {})
        targets = planner_ctx.get('targets', [])
        if targets:
            host = targets[0].get('primary_ref')
        else:
            # Fallback to legacy recon data
            recon = data.get("recon", {}) if isinstance(data.get("recon"), dict) else {}
            domains = recon.get("domains", []) if isinstance(recon.get("domains"), list) else []
            host = self._first_list_value(domains)

        if not host:
            logger.debug("No target host found for ServiceEnumeration proposal")
            return None

        params = {"target_host": host}
        return ActionProposal(
            name="ServiceEnumeration",
            description="Enumerate exposed services on a known host.",
            parameters=params,
            score=1.0,
        )

    def _propose_exploit_attempt(self, state: AttackStateLike) -> Optional[ActionProposal]:
        data = state.state_data or {}
        enumeration = (
            data.get("enumeration", {}) if isinstance(data.get("enumeration"), dict) else {}
        )
        services = (
            enumeration.get("services", {})
            if isinstance(enumeration.get("services"), dict)
            else {}
        )
        if not services:
            logger.debug("No enumerated services present for ExploitAttempt proposal")
            return None

        host = self._first_dict_key(services)
        # Deterministic placeholder vulnerability id for Phase 1 simulation
        vuln_id = "SIM-EX-001"
        params = {"target_host": host, "vulnerability_id": vuln_id}
        return ActionProposal(
            name="ExploitAttempt",
            description="Attempt a simulated exploit against an identified vulnerability.",
            parameters=params,
            score=1.0,
        )

    def _propose_privilege_escalation(self, state: AttackStateLike) -> Optional[ActionProposal]:
        data = state.state_data or {}
        exploitation = (
            data.get("exploitation", {}) if isinstance(data.get("exploitation"), dict) else {}
        )
        compromised = (
            exploitation.get("compromised_hosts", {})
            if isinstance(exploitation.get("compromised_hosts"), dict)
            else {}
        )
        if not compromised:
            logger.debug(
                "No compromised hosts present for PrivilegeEscalation proposal"
            )
            return None

        host = self._first_dict_key(compromised)
        params = {"target_host": host}
        return ActionProposal(
            name="PrivilegeEscalation",
            description="Attempt to escalate privileges on a compromised host.",
            parameters=params,
            score=1.0,
        )

    def _propose_proof_of_compromise(self, state: AttackStateLike) -> Optional[ActionProposal]:
        # Require evidence of prior privilege escalation to align with policy prerequisites
        data = state.state_data or {}
        pe = (
            data.get("privilege_escalation", {})
            if isinstance(data.get("privilege_escalation"), dict)
            else {}
        )
        if not pe:
            logger.debug("No privilege escalation data for ProofOfCompromise proposal")
            return None

        params = {"evidence_tag": "simulated-artifact"}
        return ActionProposal(
            name="ProofOfCompromise",
            description="Generate a simulated proof artifact indicating compromise.",
            parameters=params,
            score=1.0,
        )

    @staticmethod
    def _first_list_value(values: Iterable[Any]) -> Any:
        # Deterministic selection: by stringified sort order
        try:
            sorted_values = sorted(values, key=lambda v: str(v))
            return sorted_values[0]
        except Exception:
            # Fallback to next(iter(...)) if sorting fails
            for v in values:
                return v
            return None

    @staticmethod
    def _first_dict_key(d: Mapping[str, Any]) -> Optional[str]:
        try:
            keys = sorted(d.keys())
            return keys[0] if keys else None
        except Exception:
            for k in d.keys():
                return k
            return None


__all__ = [
    "DecisionEngine",
    "ActionProposal",
]
