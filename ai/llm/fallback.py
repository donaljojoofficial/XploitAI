"""
Fallback LLM Adapter implementation.
"""
from __future__ import annotations

import logging
import time
from typing import Iterator, Optional, List

from ai.llm.base import BaseLLMAdapter
from ai.schemas import Decision, DecisionInput, Plan

logger = logging.getLogger(__name__)


class FallbackAdapter(BaseLLMAdapter):
    """
    Adapter that delegates to a list of other adapters in order.
    If the first adapter fails (returns None), it tries the next.
    """

    def __init__(self, adapters: Optional[List[BaseLLMAdapter]] = None):
        self.adapters = [a for a in (adapters or []) if a is not None]
        self._adapter_failures: dict[int, int] = {}
        self._adapter_disabled_until: dict[int, float] = {}
        if not self.adapters:
            logger.info("FallbackAdapter initialized with no valid adapters. LLM recommendation will be disabled.")

    def get_recommendation(
        self,
        decision_input: DecisionInput,
        next_step_hint: dict = None,
        task_key: Optional[str] = None,
    ) -> Optional[Decision]:
        if not self.adapters:
            return None

        for adapter in self.adapters:
            if self._is_temporarily_disabled(adapter):
                continue
            result = adapter.get_recommendation(
                decision_input,
                next_step_hint=next_step_hint,
                task_key=task_key,
            )
            if result:
                self._mark_success(adapter)
                return result
            self._mark_failure(adapter, "recommendation")
            logger.warning(f"Adapter {adapter.__class__.__name__} failed to return recommendation. Trying next...")
        logger.error("FallbackAdapter: All adapters failed to return recommendation.")
        return None

    def get_plan(
        self,
        decision_input: DecisionInput,
        task_key: Optional[str] = None,
    ) -> Optional[Plan]:
        if not self.adapters:
            return None

        for adapter in self.adapters:
            if self._is_temporarily_disabled(adapter):
                continue
            result = adapter.get_plan(decision_input, task_key=task_key)
            if result:
                self._mark_success(adapter)
                return result
            self._mark_failure(adapter, "plan")
            logger.warning(f"Adapter {adapter.__class__.__name__} failed to return plan. Trying next...")
        logger.error("FallbackAdapter: All adapters failed to return plan.")
        return None

    def explain_decision(self, decision: Decision, decision_input: DecisionInput) -> Optional[str]:
        for adapter in self.adapters:
            if self._is_temporarily_disabled(adapter):
                continue
            result = adapter.explain_decision(decision, decision_input)
            if result:
                self._mark_success(adapter)
                return result
            self._mark_failure(adapter, "explain")
        return None

    def generate(self, prompt: str) -> Optional[str]:
        for adapter in self.adapters:
            if self._is_temporarily_disabled(adapter):
                continue
            result = adapter.generate(prompt)
            if result:
                self._mark_success(adapter)
                return result
            self._mark_failure(adapter, "generate")
        return None

    def generate_stream(self, prompt: str) -> Iterator[str]:
        for adapter in self.adapters:
            if self._is_temporarily_disabled(adapter):
                continue
            try:
                yield from adapter.generate_stream(prompt)
                self._mark_success(adapter)
                return
            except Exception as e:
                self._mark_failure(adapter, "stream")
                logger.warning(f"Adapter {adapter.__class__.__name__} stream failed: {e}. Trying next...")
                continue

    def get_attack_narrative(self, decision_input: DecisionInput) -> Iterator[str]:
        for adapter in self.adapters:
            if self._is_temporarily_disabled(adapter):
                continue
            try:
                yield from adapter.get_attack_narrative(decision_input)
                self._mark_success(adapter)
                return
            except Exception:
                self._mark_failure(adapter, "narrative")
                continue

    def _is_temporarily_disabled(self, adapter: BaseLLMAdapter) -> bool:
        if adapter.__class__.__name__ == "LocalRuleEngine":
            return False

        disabled_until = self._adapter_disabled_until.get(id(adapter), 0.0)
        if disabled_until <= time.time():
            if disabled_until:
                self._adapter_disabled_until.pop(id(adapter), None)
            return False
        return True

    def _mark_success(self, adapter: BaseLLMAdapter) -> None:
        self._adapter_failures.pop(id(adapter), None)
        self._adapter_disabled_until.pop(id(adapter), None)

    def _mark_failure(self, adapter: BaseLLMAdapter, operation: str) -> None:
        if adapter.__class__.__name__ == "LocalRuleEngine":
            return

        key = id(adapter)
        failures = self._adapter_failures.get(key, 0) + 1
        self._adapter_failures[key] = failures

        cooldown = min(30 * failures, 180)
        self._adapter_disabled_until[key] = time.time() + cooldown
        logger.warning(
            "FallbackAdapter cooling down %s after %s failure for %ss.",
            adapter.__class__.__name__,
            operation,
            cooldown,
        )
