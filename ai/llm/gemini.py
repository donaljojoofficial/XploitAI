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

    def __init__(self, model_name: str = "gemini-1.5-flash"):
        self.model_name = model_name
        self.fallback_models = ["gemini-1.5-pro", "gemini-1.0-pro"]
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

    def _generate_content_with_retry(self, prompt: str):
        """Helper to generate content with fallback models on 404/503 errors."""
        if not HAS_SDK or not self.api_key:
            return None

        models_to_try = [self.model_name] + self.fallback_models
        
        for model in models_to_try:
            try:
                # Create a client for the specific model
                client = genai.GenerativeModel(model)
                response = client.generate_content(prompt)
                return response
            except Exception as e:
                error_msg = str(e)
                if "404" in error_msg or "503" in error_msg or "not found" in error_msg.lower():
                    logger.warning(f"Gemini model '{model}' failed: {e}. Retrying with next model.")
                    continue
                logger.error(f"Gemini call failed for model '{model}': {e}")
                return None
        
        logger.error("All Gemini models failed.")
        return None

    def get_recommendation(self, decision_input: DecisionInput) -> Optional[Decision]:
        logger.info("GeminiAdapter: invoking Gemini Flash model for recommendation")
        try:
            # Construct prompt
            prompt = self._build_recommendation_prompt(decision_input)

            # Call API
            response = self._generate_content_with_retry(prompt)
            if not response:
                return None
            logger.info("GeminiAdapter: received response from Gemini")

            # Parse response
            return self._parse_decision(response.text)
        except Exception as e:
            logger.error(f"GeminiAdapter: Gemini call failed, returning None. Error: {e}")
            return None

    def get_plan(self, decision_input: DecisionInput) -> Optional[Plan]:
        logger.info("GeminiAdapter: invoking Gemini Flash model for plan")
        try:
            prompt = self._build_plan_prompt(decision_input)
            response = self._generate_content_with_retry(prompt)
            if not response:
                return None
            logger.info("GeminiAdapter: received plan response from Gemini")
            return self._parse_plan(response.text)
        except Exception as e:
            logger.error(f"GeminiAdapter: Gemini planning failed, returning None. Error: {e}")
            return None

    def explain_decision(
        self, decision: Decision, decision_input: DecisionInput
    ) -> Optional[str]:
        logger.info("GeminiAdapter: invoking Gemini Flash model for explanation")
        try:
            prompt = (
                f"Context: {decision_input}\n"
                f"Decision: {decision}\n"
                "Explain why this decision is appropriate in 2-3 sentences."
            )
            response = self._generate_content_with_retry(prompt)
            if not response:
                return None
            logger.info("GeminiAdapter: received explanation from Gemini")
            return response.text
        except Exception as e:
            logger.error(f"GeminiAdapter: Gemini explanation failed. Error: {e}")
            return None

    def generate(self, prompt: str) -> Optional[str]:
        logger.info("GeminiAdapter: invoking Gemini for raw generation")
        try:
            response = self._generate_content_with_retry(prompt)
            if not response:
                return None
            return response.text
        except Exception as e:
            logger.error(f"GeminiAdapter: generation failed. Error: {e}")
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