"""
Gemini LLM Adapter implementation.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Optional

from ai.llm.base import BaseLLMAdapter
from ai.schemas import Decision, DecisionInput, Plan

logger = logging.getLogger(__name__)

# Conditional import to ensure import-safety if SDK is missing
try:
    import google.generativeai as genai

    HAS_SDK = True
except ImportError:
    HAS_SDK = False


class GeminiAdapter(BaseLLMAdapter):
    """Adapter for Google's Gemini models via google-generativeai SDK."""

    def __init__(self, model_name: str = "models/gemini-1.5-flash"):
        self.model_name = model_name
        self.api_key = os.getenv("GEMINI_API_KEY")
        self._client = None

        if HAS_SDK and self.api_key:
            try:
                genai.configure(api_key=self.api_key)
                self._client = genai.GenerativeModel(model_name)
            except Exception as e:
                logger.error(f"Failed to initialize Gemini client: {e}")
        elif not HAS_SDK:
            logger.warning("google-generativeai SDK not found. GeminiAdapter disabled.")
        elif not self.api_key:
            logger.warning("GEMINI_API_KEY not set. GeminiAdapter disabled.")

    def get_recommendation(self, decision_input: DecisionInput) -> Optional[Decision]:
        if not self._client:
            logger.warning("GeminiAdapter: client not initialized")
            return None

        logger.info("GeminiAdapter: invoking Gemini Flash model for recommendation")
        try:
            # Construct prompt
            prompt = self._build_recommendation_prompt(decision_input)

            # Call API
            response = self._client.generate_content(prompt)
            logger.info("GeminiAdapter: received response from Gemini")

            # Parse response
            return self._parse_decision(response.text)
        except Exception as e:
            logger.error(f"GeminiAdapter: Gemini call failed, returning None. Error: {e}")
            return None

    def get_plan(self, decision_input: DecisionInput) -> Optional[Plan]:
        if not self._client:
            logger.warning("GeminiAdapter: client not initialized")
            return None

        logger.info("GeminiAdapter: invoking Gemini Flash model for plan")
        try:
            prompt = self._build_plan_prompt(decision_input)
            response = self._client.generate_content(prompt)
            logger.info("GeminiAdapter: received plan response from Gemini")
            return self._parse_plan(response.text)
        except Exception as e:
            logger.error(f"GeminiAdapter: Gemini planning failed, returning None. Error: {e}")
            return None

    def explain_decision(
        self, decision: Decision, decision_input: DecisionInput
    ) -> Optional[str]:
        if not self._client:
            return None

        logger.info("GeminiAdapter: invoking Gemini Flash model for explanation")
        try:
            prompt = (
                f"Context: {decision_input}\n"
                f"Decision: {decision}\n"
                "Explain why this decision is appropriate in 2-3 sentences."
            )
            response = self._client.generate_content(prompt)
            logger.info("GeminiAdapter: received explanation from Gemini")
            return response.text
        except Exception as e:
            logger.error(f"GeminiAdapter: Gemini explanation failed. Error: {e}")
            return None

    def _build_recommendation_prompt(self, decision_input: DecisionInput) -> str:
        return (
            f"Context: {decision_input}\n"
            "Task: Recommend the single best next penetration testing action.\n"
            "Output: A single valid JSON object. NO markdown formatting.\n"
            "Schema: { \"action_type\": \"<ActionName>\", \"parameters\": { ... }, \"rationale\": \"<short explanation>\" }\n"
            "Ensure the action_type matches a known tool or tactic."
        )

    def _build_plan_prompt(self, decision_input: DecisionInput) -> str:
        return (
            f"Context: {decision_input}\n"
            "Task: Create a multi-step attack plan.\n"
            "Output: A single valid JSON object matching the Plan schema. NO markdown.\n"
            "Schema: { \"steps\": [ { \"action_type\": \"...\", \"parameters\": {...}, \"rationale\": \"...\" } ] }\n"
            "Keep steps logical and sequential."
        )

    def _parse_decision(self, text: str) -> Optional[Decision]:
        try:
            clean_text = text.replace("```json", "").replace("```", "").strip()
            data = json.loads(clean_text)
            return Decision(**data)
        except Exception:
            return None

    def _parse_plan(self, text: str) -> Optional[Plan]:
        try:
            clean_text = text.replace("```json", "").replace("```", "").strip()
            data = json.loads(clean_text)
            return Plan(**data)
        except Exception:
            return None