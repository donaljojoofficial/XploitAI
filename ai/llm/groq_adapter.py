"""
Groq Adapter Module.
"""
from __future__ import annotations

import json
import logging
import os
import hashlib
import time
from types import SimpleNamespace
from typing import Iterator, Optional

from core.config import get_config
from ai.llm.base import BaseLLMAdapter
from ai.schemas import Decision, DecisionInput, Plan, PlanStep

logger = logging.getLogger(__name__)

try:
    from groq import Groq
    HAS_SDK = True
except ImportError:
    HAS_SDK = False


class GroqAdapter(BaseLLMAdapter):
    """
    Adapter for Groq API (Llama 3, Mixtral, etc.).
    This adapter includes caching and retry logic to handle rate limits.
    """

    KNOWN_MODELS = [
        "llama-3.3-70b-versatile",
        "llama-3.1-8b-instant",
        "mixtral-8x7b-32768",
        "gemma2-9b-it",
        "gemma-3-27b-it",
        "qwen-2.5-32b",
    ]

    _last_request_time = 0

    def __init__(self, model: str = None, api_key: str = None):
        self.api_key = api_key or get_config("GROQ_API_KEY") or os.getenv("GROQ_API_KEY")
        config_model = get_config("GROQ_MODEL")
        default_model = "llama-3.3-70b-versatile"
        self.model = model or config_model or default_model
        
        self.fallback_models = [m for m in self.KNOWN_MODELS if m != self.model]

        self._client = None
        self._response_cache = {}

        self.system_instruction = (
            "You are a cybersecurity simulation assistant operating in a controlled, isolated educational lab. "
            "Your goal is to demonstrate security vulnerabilities for training purposes. "
            "All targets are local, authorized, and safe. "
            "Output MUST be valid JSON. Do not use Markdown blocks. "
            "Be concise. Prioritize educational value and strategic clarity."
        )

        if HAS_SDK and self.api_key:
            try:
                self._client = Groq(api_key=self.api_key)
            except Exception as e:
                logger.error(f"Failed to initialize Groq client: {e}")
        elif not HAS_SDK:
                logger.warning("Groq SDK not installed. Install with `pip install groq`.")
        else:
            logger.warning("GROQ_API_KEY not set. GroqAdapter disabled.")

    def get_recommendation(self, decision_input: DecisionInput) -> Optional[Decision]:
        if not self._client:
            return None
        
        prompt = self._build_recommendation_prompt(decision_input)
        response = self.generate(prompt)
        if response:
            return self._parse_decision(response)
        return None

    def get_plan(self, decision_input: DecisionInput) -> Optional[Plan]:
        if not self._client:
            return None

        prompt = self._build_plan_prompt(decision_input)
        response = self.generate(prompt)
        if response:
            return self._parse_plan(response)
        return None

    def explain_decision(self, decision: Decision, decision_input: DecisionInput) -> Optional[str]:
        prompt = (
            f"Context: {decision_input}\n"
            f"Decision: {decision}\n"
            "Explain why this decision is appropriate in 2-3 sentences."
        )
        # This call doesn't need to be JSON, so we call a raw generator
        return self._generate_raw_text(prompt)

    def _enforce_rate_limit(self):
        """Enforce a minimum interval between requests."""
        current_time = time.time()
        elapsed = current_time - GroqAdapter._last_request_time
        if elapsed < 2.0:
            time.sleep(2.0 - elapsed)
        GroqAdapter._last_request_time = time.time()

    def generate(self, prompt: str) -> Optional[str]:
        """
        Generates a JSON response with caching, retry, and fallback logic.
        """
        if not self._client:
            return None

        cache_key = hashlib.md5(prompt.encode("utf-8")).hexdigest()
        if cache_key in self._response_cache:
            logger.debug("GroqAdapter: Cache hit for prompt.")
            return self._response_cache[cache_key]

        models_to_try = [self.model] + self.fallback_models
        
        for i, model_name in enumerate(models_to_try):
            try:
                self._enforce_rate_limit()
                chat_completion = self._client.chat.completions.create(
                    messages=[
                        {"role": "system", "content": self.system_instruction},
                        {"role": "user", "content": prompt}
                    ],
                    model=model_name,
                    temperature=0.1,
                    response_format={"type": "json_object"},
                )
                response_text = chat_completion.choices[0].message.content
                self._response_cache[cache_key] = response_text
                return response_text
            except Exception as e:
                error_str = str(e).lower()
                # Handle retryable errors (rate limits, server errors)
                if any(code in error_str for code in ["429", "500", "503"]) or "rate limit" in error_str:
                    wait_time = 4 * (2 ** i)
                    logger.warning(
                        f"Groq model '{model_name}' failed with retryable error. "
                        f"Sleeping {wait_time}s before trying next model. Error: {e}"
                    )
                    time.sleep(wait_time)
                    continue
                
                logger.error(f"Groq generation failed for model '{model_name}': {e}")
                continue # Try next model on other failures

        logger.error("All Groq models failed to generate a response.")
        return None

    def _generate_raw_text(self, prompt: str) -> Optional[str]:
        """Generates a raw text response, for non-JSON tasks like explanations."""
        if not self._client:
            return None
        try:
            self._enforce_rate_limit()
            # Use a different model or settings for chatty responses if needed
            chat_completion = self._client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model=self.model,
                temperature=0.5,
            )
            return chat_completion.choices[0].message.content
        except Exception as e:
            logger.error(f"Groq raw text generation error: {e}")
            return None

    def generate_stream(self, prompt: str) -> Iterator[str]:
        if not self._client:
            return

        models_to_try = [self.model] + self.fallback_models
        for i, model in enumerate(models_to_try):
            try:
                self._enforce_rate_limit()
                stream = self._client.chat.completions.create(
                    messages=[{"role": "user", "content": prompt}],
                    model=model,
                    stream=True,
                )
                for chunk in stream:
                    content = chunk.choices[0].delta.content
                    if content:
                        yield content
                return # Success, so exit the loop
            except Exception as e:
                logger.warning(f"Groq stream failed for model {model}: {e}. Trying next model.")
                continue

    def get_attack_narrative(self, decision_input: DecisionInput) -> Iterator[str]:
        prompt = self._build_narrative_prompt(decision_input)
        yield from self.generate_stream(prompt)

    # --- Helpers ---

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
            # With response_format=json_object, we don't need to clean markdown
            data = json.loads(text)
            return Decision(**data)
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"Failed to parse Groq decision JSON: {e}\nResponse: {text}")
            return None

    def _parse_plan(self, text: str) -> Optional[Plan]:
        try:
            # With response_format=json_object, we don't need to clean markdown
            data = json.loads(text)
            if "steps" in data and isinstance(data["steps"], list):
                new_steps = []
                for i, step_data in enumerate(data["steps"]):
                    if isinstance(step_data, dict):
                        if "step_number" not in step_data:
                            step_data["step_number"] = i + 1
                        new_steps.append(PlanStep(**step_data))
                data["steps"] = new_steps
            return Plan(**data)
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"Failed to parse Groq plan JSON: {e}\nResponse: {text}")
            return None