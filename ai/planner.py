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
        self.action_graph = self._load_json_file("actions/action_graph.json")
        self.command_map = self._load_json_file("actions/command_map.json")

    def _get_adapter(self, provider: str) -> BaseLLMAdapter:
        if provider == "auto":
            # Fallback to a default if not specified in settings
            provider = getattr(settings, "DEFAULT_LLM_PROVIDER", "fallback")

        if provider == "gemini":
            return GeminiAdapter()
        # In a real scenario, you would import and instantiate other adapters
        # from ai.llm.openai import OpenAIAdapter etc.
        return FallbackAdapter()

    def _load_json_file(self, path: str) -> dict:
        try:
            with open(path, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Failed to load or parse {path}: {e}")
            return {}

    def get_next_action(self, state_manager: StateManager) -> Optional[dict]:
        """
        Determines the next action to take based on the current state and action graph.
        """
        current_state = state_manager.get_current_state_for_planner()

        completed_actions = current_state.get("completed_actions", [])
        if not completed_actions:
            valid_actions = [
                action
                for action, details in self.action_graph.items()
                if details.get("phase") == "reconnaissance"
            ]
        else:
            last_action = completed_actions[-1]
            valid_actions = self.action_graph.get(last_action, {}).get("next_actions", [])

        if not valid_actions:
            logger.info("No valid next actions found in graph. Stopping.")
            return None

        valid_actions = [a for a in valid_actions if a in self.command_map]
        if not valid_actions:
            logger.warning("No executable actions found for the current state. Stopping.")
            return None

        attack_state_obj = state_manager.get_attack_state()
        past_actions_summary = [
            PastActionSummary(action_type=a, parameters={}) for a in completed_actions
        ]

        decision_input = DecisionInput(
            phase=attack_state_obj.current_phase,
            known_services=[],
            past_actions=past_actions_summary,
            findings=current_state.get("findings"),
        )

        try:
            proposal = self.adapter.get_recommendation(
                decision_input,
                next_step_hint={"allowed_actions": valid_actions},
            )

            if proposal and proposal.action_type in valid_actions:
                return {
                    "name": proposal.action_type,
                    "parameters": proposal.parameters,
                    "reasoning": proposal.rationale,
                }
            raise ValueError("LLM proposed an invalid or no action.")
        except Exception as e:
            logger.warning(f"AI planning failed ({e}). Falling back to first valid action.")
            action_name = valid_actions[0]
            return {"name": action_name, "parameters": {}, "reasoning": "Fallback selection."}