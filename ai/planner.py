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

        if provider == "gemini" and any(isinstance(a, GeminiAdapter) for a in adapters):
            return next(a for a in adapters if isinstance(a, GeminiAdapter))
        elif provider == "claude" and any(isinstance(a, AnthropicAdapter) for a in adapters):
            return next(a for a in adapters if isinstance(a, AnthropicAdapter))
        elif provider == "groq" and any(isinstance(a, GroqAdapter) for a in adapters):
            return next(a for a in adapters if isinstance(a, GroqAdapter))
        elif provider == "ollama" and any(isinstance(a, OllamaAdapter) for a in adapters):
            return next(a for a in adapters if isinstance(a, OllamaAdapter))

        if not adapters:
            logger.info("No LLM providers available in AIPlanner. Falling back to deterministic action selection.")
            return None

        from ai.llm.fallback import FallbackAdapter
        return FallbackAdapter(adapters)

    def get_next_command(self, state_manager: StateManager) -> Optional[dict]:
        """Determines the next command ID to execute. AI sees only metadata, not templates."""
        from core.models import Command

        current_state = state_manager.get_current_state_for_planner()
        phase = current_state.get("current_phase")

        available_commands = list(state_manager.get_available_commands(phase))
        if not available_commands:
            logger.info("No available commands for current phase. Stopping.")
            return None

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
        if self.adapter:
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

        # Fallback deterministic selection
        chosen = available_commands[0]

        return {
            "command_id": chosen.id,
            "command_name": chosen.name,
            "reason": chosen.description or "Fallback selection of first available command.",
        }
