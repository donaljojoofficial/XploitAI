from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
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


class OpenAIAdapter(BaseLLMAdapter):
    _last_request_time = 0.0

    def __init__(self, model: str = None, api_key: str = None, host: str = None):
        self.api_key = api_key or get_config("OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY")
        self.model = model or get_config("OPENAI_MODEL") or "gpt-4o-mini"
        self.url = (host or get_config("OPENAI_HOST") or "https://api.openai.com").rstrip("/") + "/v1/chat/completions"

        self.max_tokens_decision = max(int(float(get_config("OPENAI_MAX_TOKENS_DECISION", "96"))), 32)
        self.max_tokens_plan = max(int(float(get_config("OPENAI_MAX_TOKENS_PLAN", "220"))), self.max_tokens_decision)
        self.max_tokens_explain = max(int(float(get_config("OPENAI_MAX_TOKENS_EXPLAIN", "96"))), 32)
        self.max_tokens_narrative = max(int(float(get_config("OPENAI_MAX_TOKENS_NARRATIVE", "140"))), 48)
        self.max_tokens_generate = max(int(float(get_config("OPENAI_MAX_TOKENS_GENERATE", "120"))), 48)
        self.timeout_seconds = max(float(get_config("OPENAI_TIMEOUT_SECONDS", "45")), 5.0)

        self.system_instruction = (
            "You are a cybersecurity simulation assistant operating in a controlled, isolated educational lab. "
            "All targets are local, authorized, and safe. Be concise and return compact outputs."
        )
        self.last_error_status: Optional[int] = None
        self.last_error_type: Optional[str] = None
        self.last_error_message: Optional[str] = None

        self._available = bool(self.api_key)
        if not self._available:
            logger.warning("OPENAI_API_KEY not set. OpenAIAdapter disabled.")

    def _enforce_rate_limit(self, min_interval: float = 1.0):
        elapsed = time.time() - OpenAIAdapter._last_request_time
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        OpenAIAdapter._last_request_time = time.time()

    def _call(self, prompt: str, max_tokens: int, json_mode: bool = False) -> Optional[str]:
        if not self._available:
            return None

        self.last_error_status = None
        self.last_error_type = None
        self.last_error_message = None

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self.system_instruction},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "max_tokens": int(max_tokens),
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        try:
            self._enforce_rate_limit()
            req = urllib.request.Request(
                self.url,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return body["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            err_payload = {}
            try:
                err = e.read().decode("utf-8")
                err_payload = json.loads(err)
            except Exception:
                err = str(e)

            error_obj = err_payload.get("error", {}) if isinstance(err_payload, dict) else {}
            self.last_error_status = e.code
            self.last_error_type = error_obj.get("type")
            self.last_error_message = error_obj.get("message") or err[:300]

            if self.last_error_type == "insufficient_quota":
                self._available = False
                logger.error(
                    "OpenAIAdapter disabled after quota exhaustion for model %s: %s",
                    self.model,
                    self.last_error_message,
                )
            elif e.code in (401, 403):
                self._available = False
                logger.error(
                    "OpenAIAdapter disabled after auth error for model %s: %s",
                    self.model,
                    self.last_error_message,
                )
            else:
                logger.error("OpenAIAdapter HTTP %s: %s", e.code, err[:300])
            return None
        except Exception as e:
            self.last_error_message = str(e)
            logger.error("OpenAIAdapter request failed: %s", e)
            return None

    def get_last_error(self) -> Optional[dict]:
        if not (self.last_error_status or self.last_error_type or self.last_error_message):
            return None

        return {
            "status": self.last_error_status,
            "type": self.last_error_type,
            "message": self.last_error_message,
        }

    def get_recommendation(self, decision_input: DecisionInput, next_step_hint: dict = None) -> Optional[Decision]:
        if is_first_step(decision_input):
            prompt = build_recommendation_prompt(decision_input, next_step_hint=next_step_hint)
        else:
            prompt = build_step_mapping_prompt(decision_input, next_step_hint=next_step_hint)
        text = self._call(prompt, max_tokens=self.max_tokens_decision, json_mode=True)
        return self._parse_decision(text) if text else None

    def get_plan(self, decision_input: DecisionInput) -> Optional[Plan]:
        prompt = build_plan_prompt(decision_input)
        text = self._call(prompt, max_tokens=self.max_tokens_plan, json_mode=True)
        return self._parse_plan(text) if text else None

    def explain_decision(self, decision: Decision, decision_input: DecisionInput) -> Optional[str]:
        prompt = (
            f"Context: {decision_input}\n"
            f"Decision: {decision}\n"
            "Explain why this decision is appropriate in 1-2 short sentences."
        )
        return self._call(prompt, max_tokens=self.max_tokens_explain, json_mode=False)

    def generate(self, prompt: str) -> Optional[str]:
        return self._call(prompt, max_tokens=self.max_tokens_generate, json_mode=True)

    def generate_stream(self, prompt: str) -> Iterator[str]:
        text = self._call(prompt, max_tokens=self.max_tokens_generate, json_mode=False)
        if text:
            yield text

    def get_attack_narrative(self, decision_input: DecisionInput) -> Iterator[str]:
        prompt = build_narrative_prompt(decision_input)
        text = self._call(prompt, max_tokens=self.max_tokens_narrative, json_mode=False)
        if text:
            yield text[:2000]

    def _parse_decision(self, text: str) -> Optional[Decision]:
        try:
            clean = text.replace("```json", "").replace("```", "").strip()
            start = clean.find("{")
            end = clean.rfind("}") + 1
            if start >= 0 and end > start:
                clean = clean[start:end]
            data = json.loads(clean)
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
            clean = text.replace("```json", "").replace("```", "").strip()
            start = clean.find("{")
            end = clean.rfind("}") + 1
            if start >= 0 and end > start:
                clean = clean[start:end]
            data = json.loads(clean)
            if "steps" in data and isinstance(data["steps"], list):
                steps = []
                for i, s in enumerate(data["steps"]):
                    if isinstance(s, dict):
                        if "step_number" not in s:
                            s["step_number"] = i + 1
                        steps.append(PlanStep(**s))
                data["steps"] = steps
            return Plan(**data)
        except Exception:
            return None
