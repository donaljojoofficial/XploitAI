"""
Anthropic LLM Adapter implementation.
"""
from __future__ import annotations

import json
import logging
import os
import urllib.request
import urllib.error
from types import SimpleNamespace
from typing import Iterator, Optional

from core.config import get_config
from ai.llm.base import BaseLLMAdapter
from ai.schemas import Decision, DecisionInput, Plan

logger = logging.getLogger(__name__)

try:
    import anthropic
    HAS_SDK = True
except ImportError:
    HAS_SDK = False


class AnthropicAdapter(BaseLLMAdapter):
    """Adapter for Anthropic's Claude models."""

    def __init__(self, model_name: str = "claude-sonnet-4-5-20250929"):
        config_model = get_config("ANTHROPIC_MODEL")
        self.model_name = config_model if config_model else model_name
        
        known_models = [
            "claude-sonnet-4-5-20250929",
            "claude-opus-4-6-20260204",
            "claude-haiku-4-5-20251001"
        ]
        self.fallback_models = [m for m in known_models if m != self.model_name]
        
        self.api_key = get_config("ANTHROPIC_API_KEY")
        self._client = None
        self._use_raw_http = False

        # System prompt for consistent, structured, and concise behavior
        self.system_instruction = (
            "You are an autonomous penetration testing AI. "
            "Your goal is to audit a system for vulnerabilities safely and efficiently. "
            "Output MUST be valid JSON. Do not use Markdown blocks. "
            "Be concise. Prioritize high-level strategic decisions."
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

    def _generate_content(self, prompt: str) -> Optional[str]:
        models = [self.model_name] + self.fallback_models
        for model in models:
            if not self._client and not self._use_raw_http:
                return None
                
            if self._use_raw_http:
                result = self._generate_content_raw(prompt, model)
                if result:
                    return result
                continue
            
            try:
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
            req = urllib.request.Request(url, data=json.dumps(data).encode('utf-8'), headers=headers)
            with urllib.request.urlopen(req) as response:
                if response.status == 200:
                    resp_data = json.loads(response.read().decode('utf-8'))
                    if "content" in resp_data and len(resp_data["content"]) > 0:
                        return resp_data["content"][0]["text"]
        except Exception as e:
            logger.error(f"Anthropic raw HTTP request failed: {e}")
        return None

    def get_recommendation(self, decision_input: DecisionInput) -> Optional[Decision]:
        logger.info("AnthropicAdapter: invoking Claude for recommendation")
        prompt = self._build_recommendation_prompt(decision_input)
        text = self._generate_content(prompt)
        if not text:
            return None
        return self._parse_decision(text)

    def get_plan(self, decision_input: DecisionInput) -> Optional[Plan]:
        logger.info("AnthropicAdapter: invoking Claude for plan")
        prompt = self._build_plan_prompt(decision_input)
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
        for model in models:
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
        prompt = self._build_narrative_prompt(decision_input)
        yield from self.generate_stream(prompt)

    # --- Helpers ---

    def _build_recommendation_prompt(self, decision_input: DecisionInput) -> str:
        return (
            f"Context: {decision_input}\n"
            "Task: Recommend the single best next penetration testing action. "
            "Focus on the current phase (Recon -> Scanning -> Exploitation).\n"
            "Schema: { \"action_type\": \"<ActionName>\", \"parameters\": { ... }, \"rationale\": \"<short explanation>\" }"
        )

    def _build_plan_prompt(self, decision_input: DecisionInput) -> str:
        return (
            f"Context: {decision_input}\n"
            "Task: Create a multi-step attack plan. Batch routine tasks where possible.\n"
            "Schema: { \"steps\": [ { \"action_type\": \"...\", \"parameters\": {...}, \"rationale\": \"...\" } ] }"
        )

    def _build_narrative_prompt(self, decision_input: DecisionInput) -> str:
        return (
            f"Context: {decision_input}\n"
            "Task: Generate a detailed, real-time tactical narrative of the ongoing penetration test operation based on the provided context. "
            "Describe the current phase, the status of compromised assets, and the strategic outlook.\n"
            "Tone: Professional, objective, and technical.\n"
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
            if "steps" in data and isinstance(data["steps"], list):
                steps = []
                for i, step_data in enumerate(data["steps"]):
                    if isinstance(step_data, dict):
                        if "step_number" not in step_data:
                            step_data["step_number"] = i + 1
                        steps.append(SimpleNamespace(**step_data))
                data["steps"] = steps
            return Plan(**data)
        except Exception:
            return None