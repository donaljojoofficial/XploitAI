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
        "recommendation": ["groq", "nvidia", "openai", "gemini", "lmstudio", "local"],
        "recommendation.reconnaissance": ["groq", "nvidia", "openai", "gemini", "lmstudio", "local"],
        "recommendation.enumeration": ["groq", "nvidia", "openai", "gemini", "lmstudio", "local"],
        "recommendation.exploitation": ["nvidia", "openai", "gemini", "groq", "lmstudio", "local"],
        "recommendation.privilege_escalation": ["nvidia", "openai", "gemini", "groq", "lmstudio", "local"],
        "recommendation.proof_of_compromise": ["nvidia", "openai", "groq", "gemini", "lmstudio", "local"],
        "recommendation.retry_failed_step": ["nvidia", "openai", "groq", "gemini", "lmstudio", "local"],
        "plan": ["nvidia", "openai", "gemini", "groq", "lmstudio", "local"],
        "plan.initial": ["nvidia", "openai", "gemini", "groq", "lmstudio", "local"],
        "plan.reconnaissance": ["nvidia", "openai", "gemini", "groq", "lmstudio", "local"],
        "plan.enumeration": ["nvidia", "openai", "gemini", "groq", "lmstudio", "local"],
        "plan.exploitation": ["nvidia", "openai", "gemini", "groq", "lmstudio", "local"],
        "plan.privilege_escalation": ["nvidia", "openai", "gemini", "groq", "lmstudio", "local"],
        "plan.proof_of_compromise": ["nvidia", "openai", "gemini", "groq", "lmstudio", "local"],
        "explain": ["nvidia", "openai", "groq", "gemini", "lmstudio", "local"],
        "chat": ["nvidia", "groq", "openai", "gemini", "lmstudio", "local"],
        "chat.explain_run": ["nvidia", "groq", "openai", "gemini", "lmstudio", "local"],
        "generate": ["groq", "nvidia", "openai", "gemini", "lmstudio", "local"],
        "narrative": ["nvidia", "openai", "groq", "gemini", "lmstudio", "local"],
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

    def _resolve_task_names(self, task_name: Optional[str]) -> List[str]:
        if not task_name:
            return []

        candidates: List[str] = [task_name]
        if "." in task_name:
            family = task_name.split(".", 1)[0]
            if family not in candidates:
                candidates.append(family)
        return candidates

    def _pipeline(self, task_name: Optional[str]) -> FallbackAdapter:
        for candidate in self._resolve_task_names(task_name):
            pipeline = self._pipelines.get(candidate)
            if pipeline is not None:
                return pipeline
        return self._default_pipeline

    def get_recommendation(
        self,
        decision_input: DecisionInput,
        next_step_hint: dict = None,
        task_key: Optional[str] = None,
    ) -> Optional[Decision]:
        resolved_task_key = task_key or "recommendation"
        logger.info("TaskRouterAdapter routing recommendation task '%s'.", resolved_task_key)
        return self._pipeline(resolved_task_key).get_recommendation(
            decision_input,
            next_step_hint=next_step_hint,
            task_key=resolved_task_key,
        )

    def get_plan(
        self,
        decision_input: DecisionInput,
        task_key: Optional[str] = None,
    ) -> Optional[Plan]:
        resolved_task_key = task_key or "plan"
        logger.info("TaskRouterAdapter routing plan task '%s'.", resolved_task_key)
        return self._pipeline(resolved_task_key).get_plan(
            decision_input,
            task_key=resolved_task_key,
        )

    def explain_decision(
        self, decision: Decision, decision_input: DecisionInput
    ) -> Optional[str]:
        return self._pipeline("explain").explain_decision(decision, decision_input)

    def generate(self, prompt: str) -> Optional[str]:
        return self._pipeline("generate").generate(prompt)

    def generate_for_task(self, prompt: str, task_key: Optional[str] = None) -> Optional[str]:
        return self._pipeline(task_key or "chat").generate(prompt)

    def generate_stream(self, prompt: str) -> Iterator[str]:
        yield from self._pipeline("generate").generate_stream(prompt)

    def get_attack_narrative(self, decision_input: DecisionInput) -> Iterator[str]:
        yield from self._pipeline("narrative").get_attack_narrative(decision_input)
