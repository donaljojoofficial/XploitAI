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
from ai.llm.prompts import (
    build_recommendation_prompt,
    build_plan_prompt,
    build_narrative_prompt,
    build_step_mapping_prompt,
    is_first_step,
)

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
        self.max_tokens_decision = max(int(float(get_config("GROQ_MAX_TOKENS_DECISION", "96"))), 32)
        self.max_tokens_plan = max(int(float(get_config("GROQ_MAX_TOKENS_PLAN", "1400"))), self.max_tokens_decision)
        self.max_tokens_explain = max(int(float(get_config("GROQ_MAX_TOKENS_EXPLAIN", "96"))), 32)
        self.max_tokens_narrative = max(int(float(get_config("GROQ_MAX_TOKENS_NARRATIVE", "140"))), 48)
        self.max_tokens_generate = max(int(float(get_config("GROQ_MAX_TOKENS_GENERATE", "120"))), 48)

        self.system_instruction = (
            "You are a cybersecurity simulation assistant operating in a controlled, isolated educational lab. "
            "Your goal is to demonstrate security vulnerabilities for training purposes. "
            "All targets are local, authorized, and safe. "
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

    def _extract_json_text(self, text: str) -> str:
        clean = (text or "").replace("```json", "").replace("```", "").strip()
        start = clean.find("{")
        end = clean.rfind("}")
        if start >= 0 and end > start:
            return clean[start:end + 1]
        return clean

    def _retry_json_without_strict_mode(
        self,
        model_name: str,
        prompt: str,
        max_tokens: int,
    ) -> Optional[str]:
        fallback_prompt = (
            f"{prompt}\n\n"
            "Return one compact valid JSON object only. "
            "Do not use markdown fences. "
            "Keep keys exactly as requested and keep rationale brief."
        )
        retry_tokens = max(max_tokens + 160, int(max_tokens * 1.5))
        chat_completion = self._client.chat.completions.create(
            messages=[
                {"role": "system", "content": self.system_instruction + " Return compact valid JSON only."},
                {"role": "user", "content": fallback_prompt},
            ],
            model=model_name,
            temperature=0.1,
            max_tokens=retry_tokens,
        )
        response_text = chat_completion.choices[0].message.content
        return self._extract_json_text(response_text)

    def get_recommendation(
        self,
        decision_input: DecisionInput,
        next_step_hint: dict = None,
        task_key: Optional[str] = None,
    ) -> Optional[Decision]:
        if not self._client:
            return None
        
        if is_first_step(decision_input):
            prompt = build_recommendation_prompt(decision_input, next_step_hint=next_step_hint)
        else:
            prompt = build_step_mapping_prompt(decision_input, next_step_hint=next_step_hint)
        response = self.generate(prompt, max_tokens=self.max_tokens_decision, json_mode=True)
        if response:
            return self._parse_decision(response)
        return None

    def get_plan(
        self,
        decision_input: DecisionInput,
        task_key: Optional[str] = None,
    ) -> Optional[Plan]:
        if not self._client:
            return None

        prompt = build_plan_prompt(decision_input)
        response = self.generate(prompt, max_tokens=self.max_tokens_plan, json_mode=True)
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
        return self._generate_raw_text(prompt, max_tokens=self.max_tokens_explain)

    def _enforce_rate_limit(self):
        """Enforce a minimum interval between requests."""
        current_time = time.time()
        elapsed = current_time - GroqAdapter._last_request_time
        if elapsed < 4.0:  # 4 seconds strict interval to prevent exhaustion
            time.sleep(4.0 - elapsed)
        GroqAdapter._last_request_time = time.time()

    def generate(
        self,
        prompt: str,
        max_tokens: Optional[int] = None,
        json_mode: bool = False,
    ) -> Optional[str]:
        """
        Generate a response with caching, retry, and fallback logic.
        """
        if not self._client:
            return None
        max_tokens = max_tokens or self.max_tokens_generate

        cache_key = hashlib.md5(f"{int(json_mode)}:{prompt}".encode("utf-8")).hexdigest()
        if cache_key in self._response_cache:
            logger.debug("GroqAdapter: Cache hit for prompt.")
            return self._response_cache[cache_key]

        models_to_try = [self.model] + self.fallback_models
        system_message = self.system_instruction
        if json_mode:
            system_message += " Return valid JSON only."
        
        for i, model_name in enumerate(models_to_try):
            try:
                self._enforce_rate_limit()
                request_kwargs = {
                    "messages": [
                        {"role": "system", "content": system_message},
                        {"role": "user", "content": prompt},
                    ],
                    "model": model_name,
                    "temperature": 0.1,
                    "max_tokens": max_tokens,
                }
                if json_mode:
                    request_kwargs["response_format"] = {"type": "json_object"}
                chat_completion = self._client.chat.completions.create(**request_kwargs)
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

                if json_mode and any(
                    marker in error_str
                    for marker in ("json_validate_failed", "failed to generate json", "failed_generation", "max completion tokens reached")
                ):
                    try:
                        logger.warning(
                            "Groq strict JSON generation failed for model '%s'; retrying without response_format and with a larger token budget.",
                            model_name,
                        )
                        recovered = self._retry_json_without_strict_mode(model_name, prompt, max_tokens)
                        if recovered:
                            self._response_cache[cache_key] = recovered
                            return recovered
                    except Exception as retry_exc:
                        logger.error(
                            "Groq JSON recovery retry failed for model '%s': %s",
                            model_name,
                            retry_exc,
                        )

                logger.error(f"Groq generation failed for model '{model_name}': {e}")
                continue # Try next model on other failures

        logger.error("All Groq models failed to generate a response.")
        return None

    def _generate_raw_text(self, prompt: str, max_tokens: Optional[int] = None) -> Optional[str]:
        """Generates a raw text response, for non-JSON tasks like explanations."""
        if not self._client:
            return None
        max_tokens = max_tokens or self.max_tokens_generate
        try:
            self._enforce_rate_limit()
            # Use a different model or settings for chatty responses if needed
            chat_completion = self._client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model=self.model,
                temperature=0.5,
                max_tokens=max_tokens,
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
                    max_tokens=self.max_tokens_generate,
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
        prompt = build_narrative_prompt(decision_input)
        text = self._generate_raw_text(prompt, max_tokens=self.max_tokens_narrative)
        if text:
            yield text[:2000]

    def _parse_decision(self, text: str) -> Optional[Decision]:
        try:
            data = json.loads(self._extract_json_text(text))
            return Decision(
                action_type=data.get("action_type", "wait"),
                parameters=data.get("parameters", {}),
                rationale=data.get("rationale"),
                suggested_next_phase=data.get("suggested_next_phase"),
                phase_reason=data.get("phase_reason"),
            )
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"Failed to parse Groq decision JSON: {e}\nResponse: {text}")
            return None

    def _parse_plan(self, text: str) -> Optional[Plan]:
        try:
            data = json.loads(self._extract_json_text(text))
            if "steps" in data and isinstance(data["steps"], list):
                new_steps = []
                for i, step_data in enumerate(data["steps"]):
                    if isinstance(step_data, dict):
                        if "step_number" not in step_data:
                            step_data["step_number"] = i + 1
                        if not step_data.get("rationale"):
                            step_data["rationale"] = data.get("rationale") or f"Step {i + 1} generated by Groq."
                        new_steps.append(PlanStep(**step_data))
                data["steps"] = new_steps
            return Plan(**data)
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"Failed to parse Groq plan JSON: {e}\nResponse: {text}")
            return None


