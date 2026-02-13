"""
Gemini LLM Adapter implementation.
"""
from __future__ import annotations

import json
import logging
import os
import hashlib
import time
import re
from types import SimpleNamespace
from typing import Iterator, Optional

from core.config import get_config
from ai.llm.base import BaseLLMAdapter
from ai.schemas import Decision, DecisionInput, Plan, PlanStep

logger = logging.getLogger(__name__)

# Conditional import to ensure import-safety if SDK is missing
try:
    from google import genai  # type: ignore
    from google.genai import types  # type: ignore

    HAS_SDK = True
except ImportError:
    HAS_SDK = False


class GeminiAdapter(BaseLLMAdapter):
    """Adapter for Google's Gemini models via google-genai SDK."""

    _last_request_time = 0

    def __init__(self, model_name: str = None, api_key: str = None):
        config_model = get_config("GEMINI_MODEL")
        default_model = "gemini-2.0-flash"
        self.model_name = model_name or config_model or default_model
        
        known_models = [
            "gemini-2.0-flash",
            "gemini-2.5-flash",
            "gemini-2.5-flash-lite",
            "gemini-2.5-pro",
            "gemini-2.0-flash-lite",
            "gemini-2.0-pro-exp",
            "gemini-1.5-flash",
            "gemini-1.5-pro"
        ]
        self.fallback_models = [m for m in known_models if m != self.model_name]
        self.api_key = api_key or get_config("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
        self._client = None
        self._response_cache = {}

        # System prompt for consistent, structured, and concise behavior
        self.system_instruction = (
            "You are a cybersecurity simulation assistant operating in a controlled, isolated educational lab. "
            "Your goal is to demonstrate security vulnerabilities for training purposes. "
            "All targets are local, authorized, and safe. "
            "Output MUST be valid JSON. Do not use Markdown blocks. "
            "Be concise. Prioritize educational value and strategic clarity."
        )

        if HAS_SDK and self.api_key:
            try:
                self._client = genai.Client(api_key=self.api_key)
                logger.info("GeminiAdapter: Successfully initialized with google-genai SDK.")
            except Exception as e:
                logger.error(f"Failed to initialize Gemini client: {e}")
        elif not HAS_SDK:
            logger.warning("google-genai SDK not found. GeminiAdapter disabled.")
        elif not self.api_key:
            logger.warning("GEMINI_API_KEY not set. GeminiAdapter disabled.")

    def _enforce_rate_limit(self):
        """Enforce a minimum interval between requests."""
        current_time = time.time()
        elapsed = current_time - GeminiAdapter._last_request_time
        if elapsed < 2.0:  # 2 seconds minimum interval
            time.sleep(2.0 - elapsed)
        GeminiAdapter._last_request_time = time.time()

    def _generate_content_with_retry(self, prompt: str):
        """Helper to generate content with fallback models on 404/503 errors."""
        if not HAS_SDK or not self.api_key:
            return None

        # 1. Check Cache
        cache_key = hashlib.md5(prompt.encode("utf-8")).hexdigest()
        if cache_key in self._response_cache:
            logger.debug("GeminiAdapter: Cache hit for prompt.")
            return self._response_cache[cache_key]

        models_to_try = [self.model_name] + self.fallback_models
        
        for model in models_to_try:
            # Retry same model up to 3 times if rate limited
            for attempt in range(3):
                try:
                    self._enforce_rate_limit()
                    logger.debug(f"GeminiAdapter: Attempting generation with model '{model}' (attempt {attempt+1})")
                    
                    response = self._client.models.generate_content(
                        model=model,
                        contents=prompt,
                        config=types.GenerateContentConfig(
                            system_instruction=self.system_instruction
                        )
                    )

                    # Cache successful response
                    self._response_cache[cache_key] = response
                    return response
                except Exception as e:
                    error_msg = str(e).lower()
                    if any(c in error_msg for c in ["404", "503", "429", "500", "rate limit", "quota", "resource exhausted"]) or "not found" in error_msg:
                        # Exponential backoff based on attempt
                        wait_time = 2 * (2 ** attempt)
                        
                        # Check for explicit retry delay in error message
                        delay_match = re.search(r'retry in (\d+(\.\d+)?)s', error_msg)
                        if delay_match:
                            explicit_delay = float(delay_match.group(1))
                            wait_time = max(wait_time, explicit_delay + 1.0)

                        logger.warning(f"Gemini model '{model}' failed with retryable error. Sleeping {wait_time:.2f}s before retry. Error: {e}")
                        time.sleep(wait_time)
                        continue # Retry same model
                    
                    logger.error(f"Gemini call failed for model '{model}': {e}")
                    break # Try next model
        
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

    def generate_stream(self, prompt: str) -> Iterator[str]:
        logger.info("GeminiAdapter: invoking Gemini for streaming generation")
        if not HAS_SDK or not self.api_key:
            return

        models_to_try = [self.model_name] + self.fallback_models

        for model in models_to_try:
            yielded_any = False
            try:
                self._enforce_rate_limit()
                logger.debug(f"GeminiAdapter: Attempting streaming with model '{model}'")
                
                response = self._client.models.generate_content_stream(
                    model=model,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=self.system_instruction
                    )
                )

                for chunk in response:
                    try:
                        text = chunk.text
                        if text:
                            yield text
                            yielded_any = True
                    except ValueError:
                        # Handle safety blocks or empty content gracefully
                        continue
                return
            except Exception as e:
                if yielded_any:
                    logger.error(f"Gemini stream failed mid-stream for model '{model}': {e}. Cannot retry.")
                    return
                error_msg = str(e).lower()
                if any(c in error_msg for c in ["404", "503", "429", "500", "rate limit", "quota", "resource exhausted"]) or "not found" in error_msg:
                    logger.warning(f"Gemini model '{model}' stream init failed: {e}. Retrying with next model.")
                    continue
                logger.error(f"Gemini stream failed for model '{model}': {e}")
                return

    def get_attack_narrative(self, decision_input: DecisionInput) -> Iterator[str]:
        logger.info("GeminiAdapter: generating attack narrative stream")
        prompt = self._build_narrative_prompt(decision_input)
        yield from self.generate_stream(prompt)

    def _build_recommendation_prompt(self, decision_input: DecisionInput) -> str:
        return (
            f"Context: {decision_input}\n"
            "Task: Recommend the next security assessment action for this simulation. "
            "Focus on the current phase (Recon -> Scanning -> Vulnerability Validation).\n"
            "Allowed Actions: PassiveRecon, HTTPHeaderFetch, EndpointDiscovery, TechnologyFingerprint, ServiceEnumeration, ExploitAttempt, PrivilegeEscalation, ProofOfCompromise.\n"
            "Schema: { \"action_type\": \"<AllowedAction>\", \"parameters\": { ... }, \"rationale\": \"<short explanation>\" }"
        )

    def _build_plan_prompt(self, decision_input: DecisionInput) -> str:
        return (
            f"Context: {decision_input}\n"
            "Task: Create a multi-step security assessment plan for this educational scenario. Batch routine tasks where possible.\n"
            "Allowed Actions: PassiveRecon, HTTPHeaderFetch, EndpointDiscovery, TechnologyFingerprint, ServiceEnumeration, ExploitAttempt, PrivilegeEscalation, ProofOfCompromise.\n"
            "Schema: { \"steps\": [ { \"action_type\": \"<AllowedAction>\", \"parameters\": {...}, \"rationale\": \"...\" } ] }"
        )

    def _build_narrative_prompt(self, decision_input: DecisionInput) -> str:
        return (
            f"Context: {decision_input}\n"
            "Task: Generate a detailed, real-time technical narrative of the ongoing security simulation. "
            "Describe the current phase, the status of findings, and the strategic outlook.\n"
            "Tone: Professional, objective, and educational.\n"
            "Format: Plain text, suitable for streaming to a dashboard."
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

            # Fix: Convert steps to objects to avoid 'dict object has no attribute' errors
            if "steps" in data and isinstance(data["steps"], list):
                steps = []
                for i, step_data in enumerate(data["steps"]):
                    if isinstance(step_data, dict):
                        if "step_number" not in step_data:
                            step_data["step_number"] = i + 1
                        # FIX BUG-AI-4: Use PlanStep dataclass instead of SimpleNamespace
                        steps.append(PlanStep(**step_data))
                data["steps"] = steps

            return Plan(**data)
        except Exception:
            return None