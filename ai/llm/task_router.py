from __future__ import annotations

import logging
from typing import Dict, Iterator, List, Optional

from ai.llm.base import BaseLLMAdapter
from ai.llm.fallback import FallbackAdapter
from ai.schemas import Decision, DecisionInput, Plan

logger = logging.getLogger(__name__)


class TaskRouterAdapter(BaseLLMAdapter):
    """
    Route different LLM task types to different provider chains.
    """

    DEFAULT_ROUTES = {
        "recommendation": ["groq", "openai", "gemini", "lmstudio", "local"],
        "plan": ["openai", "gemini", "groq", "lmstudio", "local"],
        "explain": ["lmstudio", "openai", "groq", "gemini", "local"],
        "generate": ["lmstudio", "groq", "openai", "gemini", "local"],
        "narrative": ["lmstudio", "openai", "groq", "gemini", "local"],
    }

    def __init__(
        self,
        adapters_by_name: Optional[Dict[str, BaseLLMAdapter]] = None,
        task_routes: Optional[Dict[str, List[str]]] = None,
    ):
        self.adapters_by_name = {
            name: adapter
            for name, adapter in (adapters_by_name or {}).items()
            if adapter is not None
        }
        self.task_routes = dict(self.DEFAULT_ROUTES)
        if task_routes:
            self.task_routes.update(task_routes)

        self._pipelines: dict[str, FallbackAdapter] = {}
        for task_name in self.task_routes:
            self._pipelines[task_name] = self._build_pipeline(task_name)

        self._default_pipeline = self._build_pipeline(None)
        logger.info(
            "TaskRouterAdapter initialized with providers: %s",
            ", ".join(self.adapters_by_name.keys()) or "none",
        )

    def _build_pipeline(self, task_name: Optional[str]) -> FallbackAdapter:
        route_names = self.task_routes.get(task_name, []) if task_name else []
        ordered_names: List[str] = []

        for name in route_names:
            if name in self.adapters_by_name and name not in ordered_names:
                ordered_names.append(name)

        for name in self.adapters_by_name.keys():
            if name not in ordered_names:
                ordered_names.append(name)

        adapters = [self.adapters_by_name[name] for name in ordered_names]
        return FallbackAdapter(adapters)

    def _pipeline(self, task_name: str) -> FallbackAdapter:
        return self._pipelines.get(task_name, self._default_pipeline)

    def get_recommendation(
        self, decision_input: DecisionInput, next_step_hint: dict = None
    ) -> Optional[Decision]:
        return self._pipeline("recommendation").get_recommendation(
            decision_input,
            next_step_hint=next_step_hint,
        )

    def get_plan(self, decision_input: DecisionInput) -> Optional[Plan]:
        return self._pipeline("plan").get_plan(decision_input)

    def explain_decision(
        self, decision: Decision, decision_input: DecisionInput
    ) -> Optional[str]:
        return self._pipeline("explain").explain_decision(decision, decision_input)

    def generate(self, prompt: str) -> Optional[str]:
        return self._pipeline("generate").generate(prompt)

    def generate_stream(self, prompt: str) -> Iterator[str]:
        yield from self._pipeline("generate").generate_stream(prompt)

    def get_attack_narrative(self, decision_input: DecisionInput) -> Iterator[str]:
        yield from self._pipeline("narrative").get_attack_narrative(decision_input)
