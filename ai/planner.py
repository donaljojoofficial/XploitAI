import json
import logging
from typing import List, Optional

from django.conf import settings

from ai.llm.base import BaseLLMAdapter
from ai.llm.fallback import FallbackAdapter
from ai.llm.gemini import GeminiAdapter
from ai.llm.prompts import build_recommendation_prompt
from ai.schemas import DecisionInput, PastActionSummary
from state.state_manager import StateManager

logger = logging.getLogger(__name__)


class FallbackPlannerEngine:
    """Deterministic engine used when no LLM provider is available."""

    PHASE_ORDER = [
        "RECONNAISSANCE",
        "ENUMERATION",
        "EXPLOITATION",
        "PRIVILEGE_ESCALATION",
        "PROOF_OF_COMPROMISE",
        "COMPLETED",
    ]

    def __init__(self, state_manager: StateManager):
        self.state_manager = state_manager

    def _get_next_phase(self, current_phase: str) -> str:
        current_phase = current_phase.upper() if current_phase else ""
        if current_phase not in self.PHASE_ORDER:
            return "RECONNAISSANCE"

        current_index = self.PHASE_ORDER.index(current_phase)
        if current_index + 1 < len(self.PHASE_ORDER):
            return self.PHASE_ORDER[current_index + 1]

        return "COMPLETED"

    def get_next_command(self) -> Optional[dict]:
        from core.models import AttackState, Phase

        current_state = self.state_manager.get_current_state_for_planner()
        phase = current_state.get("current_phase", "RECONNAISSANCE")

        # Try current phase first
        available_commands = list(self.state_manager.get_available_commands(phase))

        if not available_commands:
            # Current phase exhausted — advance through ALL remaining DB phases
            # until we find one with available commands.
            # Use actual DB phase order (by id) rather than hardcoded list,
            # so DB phase names ("discovery", "exploitation") are used correctly.
            attack_state = AttackState.objects.get(id=self.state_manager.attack_state_id)
            all_phases = list(Phase.objects.order_by("id").values_list("name", flat=True))

            current_lower = (attack_state.current_phase or "").lower()
            # Find position of current phase in DB order
            try:
                current_idx = next(
                    i for i, p in enumerate(all_phases)
                    if p.lower() == current_lower
                )
            except StopIteration:
                current_idx = -1

            # Walk forward through remaining phases
            for next_phase_name in all_phases[current_idx + 1:]:
                cmds = list(self.state_manager.get_available_commands(next_phase_name))
                if cmds:
                    attack_state.current_phase = next_phase_name
                    attack_state.save(update_fields=["current_phase"])
                    logger.info(
                        f"FallbackPlannerEngine: phase '{phase}' exhausted, "
                        f"advancing to '{next_phase_name}'."
                    )
                    available_commands = cmds
                    phase = next_phase_name
                    break

        if not available_commands:
            # Mark as COMPLETED if all phases exhausted
            attack_state = AttackState.objects.get(id=self.state_manager.attack_state_id)
            attack_state.current_phase = "COMPLETED"
            attack_state.save(update_fields=["current_phase"])
            logger.info("FallbackPlannerEngine: all phases exhausted. Marking COMPLETED.")
            return None

        chosen = available_commands[0]
        return {
            "command_id": chosen.id,
            "command_name": chosen.name,
            "reason": f"Fallback planner selects command '{chosen.name}' in phase '{phase}'.",
        }


class AIPlanner:
    """
    Uses an action graph and an LLM to decide the next best action.
    This is part of the new local execution architecture.
    """

    def __init__(self, provider: str = "auto"):
        self.adapter = self._get_adapter(provider)

    def _get_adapter(self, provider: str) -> BaseLLMAdapter:
        from core.config import get_config
        if provider == "auto":
            # Fallback to a default if not specified in settings
            provider = get_config("DEFAULT_LLM_PROVIDER", "fallback")

        # Try specific provider first to avoid initializing others unnecessarily
        if provider == "gemini":
            try:
                from ai.llm.gemini import GeminiAdapter
                gemini = GeminiAdapter()
                if gemini._client: return gemini
            except Exception: pass
        elif provider == "claude":
            try:
                from ai.llm.anthropic import AnthropicAdapter
                claude = AnthropicAdapter()
                if claude._client or claude._use_raw_http: return claude
            except Exception: pass
        elif provider == "groq":
            try:
                from ai.llm.groq_adapter import GroqAdapter
                groq = GroqAdapter()
                if groq._client: return groq
            except Exception: pass
        elif provider == "ollama":
            try:
                from ai.llm.ollama_adapter import OllamaAdapter
                ollama = OllamaAdapter()
                if ollama._client: return ollama
            except Exception: pass

        # Local provider has no external dependency
        if provider == "local":
            from ai.llm.local_rule_engine import LocalRuleEngine
            return LocalRuleEngine()

        # If specific provider failed or "fallback" was selected, initialize all available
        adapters = []
        
        try:
            from ai.llm.gemini import GeminiAdapter
            gemini = GeminiAdapter()
            if gemini._client: adapters.append(gemini)
        except Exception: pass
        
        try:
            from ai.llm.anthropic import AnthropicAdapter
            claude = AnthropicAdapter()
            if claude._client or claude._use_raw_http: adapters.append(claude)
        except Exception: pass

        try:
            from ai.llm.groq_adapter import GroqAdapter
            groq = GroqAdapter()
            if groq._client: adapters.append(groq)
        except Exception: pass
        
        try:
            from ai.llm.ollama_adapter import OllamaAdapter
            ollama = OllamaAdapter()
            if ollama._client: adapters.append(ollama)
        except Exception: pass

        from ai.llm.local_rule_engine import LocalRuleEngine
        adapters.append(LocalRuleEngine())

        from ai.llm.fallback import FallbackAdapter
        return FallbackAdapter(adapters)

    def get_next_command(self, state_manager: StateManager) -> Optional[dict]:
        """Determines the next command ID to execute. AI sees only metadata, not templates."""

        if not self.adapter:
            logger.info("No LLM provider active; using fallback planner engine.")
            return FallbackPlannerEngine(state_manager).get_next_command()

        from core.models import Command

        current_state = state_manager.get_current_state_for_planner()
        phase = current_state.get("current_phase")

        available_commands = list(state_manager.get_available_commands(phase))
        if not available_commands:
            logger.info("No available commands for current phase. Falling back to deterministic engine.")
            return FallbackPlannerEngine(state_manager).get_next_command()

        available_command_metadata = [
            {"id": c.id, "name": c.name, "description": c.description}
            for c in available_commands
        ]

        # Build a structured DecisionInput for the policy engine / LLM.
        decision_input = DecisionInput(
            phase=phase,
            known_services=[],
            past_actions=[
                PastActionSummary(action_type=str(ac), parameters={})
                for ac in current_state.get("completed_commands", [])
            ],
            available_commands=available_command_metadata,
            findings=current_state.get("findings"),
        )

        proposal = None
        try:
            proposal = self.adapter.get_recommendation(decision_input)
        except Exception as e:
            logger.warning(f"LLM recommendation failed: {e}")

        if proposal is not None:
            chosen_name = proposal.action_type
            chosen = next((c for c in available_commands if c.name == chosen_name), None)
            if chosen:
                return {
                    "command_id": chosen.id,
                    "command_name": chosen.name,
                    "reason": proposal.rationale or "Chosen by AI recommendation.",
                }
            else:
                logger.warning(f"LLM proposed unknown command: {chosen_name}")

        logger.info("Fallback planner engine engaged after LLM fallback.")
        return FallbackPlannerEngine(state_manager).get_next_command()