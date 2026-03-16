"""
Fallback LLM Adapter implementation.
"""
from __future__ import annotations

import logging
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
        if not self.adapters:
            logger.warning("FallbackAdapter initialized with no valid adapters.")

    def get_recommendation(self, decision_input: DecisionInput) -> Optional[Decision]:
        for adapter in self.adapters:
            result = adapter.get_recommendation(decision_input)
            if result:
                return result
            logger.warning(f"Adapter {adapter.__class__.__name__} failed to return recommendation. Trying next...")
        logger.error("FallbackAdapter: All adapters failed to return recommendation.")
        return None

    def get_plan(self, decision_input: DecisionInput) -> Optional[Plan]:
        for adapter in self.adapters:
            result = adapter.get_plan(decision_input)
            if result:
                return result
            logger.warning(f"Adapter {adapter.__class__.__name__} failed to return plan. Trying next...")
        logger.error("FallbackAdapter: All adapters failed to return plan.")
        return None

    def explain_decision(self, decision: Decision, decision_input: DecisionInput) -> Optional[str]:
        for adapter in self.adapters:
            result = adapter.explain_decision(decision, decision_input)
            if result:
                return result
        return None

    def generate(self, prompt: str) -> Optional[str]:
        for adapter in self.adapters:
            result = adapter.generate(prompt)
            if result:
                return result
        return None

    def generate_stream(self, prompt: str) -> Iterator[str]:
        for adapter in self.adapters:
            try:
                yield from adapter.generate_stream(prompt)
                return
            except Exception as e:
                logger.warning(f"Adapter {adapter.__class__.__name__} stream failed: {e}. Trying next...")
                continue

    def get_attack_narrative(self, decision_input: DecisionInput) -> Iterator[str]:
        for adapter in self.adapters:
            try:
                yield from adapter.get_attack_narrative(decision_input)
                return
            except Exception:
                continue