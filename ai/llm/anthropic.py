"""
Anthropic LLM Adapter implementation.
"""
from __future__ import annotations

import json
import logging
import os
import urllib.request
import time
import urllib.error
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
    import anthropic
    HAS_SDK = True
except ImportError:
    HAS_SDK = False


class AnthropicAdapter(BaseLLMAdapter):
    """Adapter for Anthropic's Claude models."""

    _last_request_time = 0

    def __init__(self, model_name: str = None, api_key: str = None):
        config_model = get_config("ANTHROPIC_MODEL")
        default_model = "claude-3-5-sonnet-20240620"
        self.model_name = model_name or config_model or default_model
        
        known_models = [
            "claude-3-5-sonnet-20240620",
            "claude-3-opus-20240229",
            "claude-3-haiku-20240307",
            "claude-sonnet-4-5-20250929",
            "claude-opus-4-6-20260204",
            "claude-haiku-4-5-20251001"
        ]
        self.fallback_models = [m for m in known_models if m != self.model_name]
        
        self.api_key = api_key or get_config("ANTHROPIC_API_KEY")
        self._client = None
        self._use_raw_http = False

        # System prompt for consistent, structured, and concise behavior
        self.system_instruction = (
            "You are a cybersecurity simulation assistant operating in a controlled, isolated educational lab. "
            "Your goal is to demonstrate security vulnerabilities for training purposes. "
            "All targets are local, authorized, and safe. "
            "Be concise. Prioritize educational value and strategic clarity."
        )

        if HAS_SDK and self.api_key:
            try:
                self._client = anthropic.Anthropic(api_key=self.api_key)
            except Exception as e:
                logger.error(f"Failed to initialize Anthropic client: {e}")
        elif self.api_key:
            self._use_raw_http = True
            logger.info("Anthropic SDK not found. Using raw HTTP fallback.")
        else:
            logger.warning("ANTHROPIC_API_KEY not set. AnthropicAdapter disabled.")

    def _enforce_rate_limit(self):
        """Enforce a minimum interval between requests."""
        current_time = time.time()
        elapsed = current_time - AnthropicAdapter._last_request_time
        if elapsed < 4.0:  # 4 seconds strict interval to prevent exhaustion
            time.sleep(4.0 - elapsed)
        AnthropicAdapter._last_request_time = time.time()

    def _generate_content(self, prompt: str) -> Optional[str]:
        models = [self.model_name] + self.fallback_models
        for i, model in enumerate(models):
            if not self._client and not self._use_raw_http:
                return None
                
            if self._use_raw_http:
                result = self._generate_content_raw(prompt, model)
                if result:
                    return result
                continue
            
            try:
                self._enforce_rate_limit()
                message = self._client.messages.create(
                    model=model,
                    max_tokens=4096,
                    system=self.system_instruction,
                    messages=[
                        {"role": "user", "content": prompt}
                    ]
                )
                if message.content and len(message.content) > 0:
                    return message.content[0].text
            except Exception as e:
                error_msg = str(e).lower()
                if "rate limit" in error_msg or "429" in error_msg:
                    wait_time = 4 * (2 ** i)
                    logger.warning(f"Anthropic rate limit for {model}. Sleeping {wait_time}s.")
                    time.sleep(wait_time)
                else:
                    logger.warning(f"Anthropic generation failed for {model}: {e}")
                continue
        
        return None

    def _generate_content_raw(self, prompt: str, model: str = None) -> Optional[str]:
        target_model = model or self.model_name
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        data = {
            "model": target_model,
            "max_tokens": 4096,
            "system": self.system_instruction,
            "messages": [{"role": "user", "content": prompt}]
        }
        
        try:
            self._enforce_rate_limit()
            req = urllib.request.Request(url, data=json.dumps(data).encode('utf-8'), headers=headers)
            with urllib.request.urlopen(req) as response:
                if response.status == 200:
                    resp_data = json.loads(response.read().decode('utf-8'))
                    if "content" in resp_data and len(resp_data["content"]) > 0:
                        return resp_data["content"][0]["text"]
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8')
            logger.error(f"Anthropic raw HTTP request failed: {e} - Body: {error_body}")
        except Exception as e:
            logger.error(f"Anthropic raw HTTP request failed: {e}")
        return None

    def get_recommendation(self, decision_input: DecisionInput, next_step_hint: dict = None) -> Optional[Decision]:
        logger.info("AnthropicAdapter: invoking Claude for recommendation")
        if is_first_step(decision_input):
            prompt = build_recommendation_prompt(decision_input, next_step_hint=next_step_hint)
        else:
            prompt = build_step_mapping_prompt(decision_input, next_step_hint=next_step_hint)
        text = self._generate_content(prompt)
        if not text:
            return None
        return self._parse_decision(text)

    def get_plan(self, decision_input: DecisionInput) -> Optional[Plan]:
        logger.info("AnthropicAdapter: invoking Claude for plan")
        prompt = build_plan_prompt(decision_input)
        text = self._generate_content(prompt)
        if not text:
            return None
        return self._parse_plan(text)

    def explain_decision(self, decision: Decision, decision_input: DecisionInput) -> Optional[str]:
        logger.info("AnthropicAdapter: invoking Claude for explanation")
        prompt = (
            f"Context: {decision_input}\n"
            f"Decision: {decision}\n"
            "Explain why this decision is appropriate in 2-3 sentences."
        )
        return self._generate_content(prompt)

    def generate(self, prompt: str) -> Optional[str]:
        return self._generate_content(prompt)

    def generate_stream(self, prompt: str) -> Iterator[str]:
        models = [self.model_name] + self.fallback_models
        for i, model in enumerate(models):
            if not self._client and not self._use_raw_http:
                return
                
            if self._use_raw_http:
                # Raw HTTP fallback does not support streaming yet, yield full text
                text = self._generate_content_raw(prompt, model)
                if text:
                    yield text
                    return
                continue
            
            try:
                self._enforce_rate_limit()
                with self._client.messages.stream(
                    max_tokens=4096,
                    system=self.system_instruction,
                    messages=[{"role": "user", "content": prompt}],
                    model=model,
                ) as stream:
                    for text in stream.text_stream:
                        yield text
                return
            except Exception as e:
                logger.warning(f"Anthropic stream failed for {model}: {e}")
                continue

    def get_attack_narrative(self, decision_input: DecisionInput) -> Iterator[str]:
        prompt = build_narrative_prompt(decision_input)
        yield from self.generate_stream(prompt)

    def _parse_decision(self, text: str) -> Optional[Decision]:
        try:
            clean_text = text.replace("```json", "").replace("```", "").strip()
            start = clean_text.find("{")
            end = clean_text.rfind("}")
            if start != -1 and end != -1 and start < end:
                clean_text = clean_text[start : end + 1]
            data = json.loads(clean_text)
            return Decision(
                action_type=data.get("action_type", "wait"),
                parameters=data.get("parameters", {}),
                rationale=data.get("rationale"),
                suggested_next_phase=data.get("suggested_next_phase"),
                phase_reason=data.get("phase_reason"),
            )
        except Exception:
            return None

    def _parse_plan(self, text: str) -> Optional[Plan]:
        try:
            clean_text = text.replace("```json", "").replace("```", "").strip()
            data = json.loads(clean_text)
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
