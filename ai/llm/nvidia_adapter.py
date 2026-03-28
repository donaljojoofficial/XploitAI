from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from typing import Iterator, Optional

from ai.llm.base import BaseLLMAdapter
from ai.llm.prompts import (
    build_narrative_prompt,
    build_plan_prompt,
    build_recommendation_prompt,
    build_step_mapping_prompt,
    is_first_step,
)
from ai.schemas import Decision, DecisionInput, Plan, PlanStep
from core.config import get_config

logger = logging.getLogger(__name__)


class NvidiaAdapter(BaseLLMAdapter):
    _last_request_time = 0.0

    def __init__(self, model: str = None, api_key: str = None, host: str = None):
        self.model = model or get_config("NVIDIA_MODEL") or "mistralai/mistral-small-4-119b-2603"
        self.host = (host or get_config("NVIDIA_HOST") or "https://integrate.api.nvidia.com").rstrip("/")
        self.url = f"{self.host}/v1/chat/completions"
        self.model_key_env_var = self._model_to_env_var(self.model)
        self.api_key = api_key or os.getenv(self.model_key_env_var) or get_config("NVIDIA_API_KEY") or os.getenv("NVIDIA_API_KEY")

        self.max_tokens_decision = max(int(float(get_config("NVIDIA_MAX_TOKENS_DECISION", "160"))), 32)
        self.max_tokens_plan = max(int(float(get_config("NVIDIA_MAX_TOKENS_PLAN", "1200"))), self.max_tokens_decision)
        self.max_tokens_explain = max(int(float(get_config("NVIDIA_MAX_TOKENS_EXPLAIN", "120"))), 32)
        self.max_tokens_narrative = max(int(float(get_config("NVIDIA_MAX_TOKENS_NARRATIVE", "180"))), 48)
        self.max_tokens_generate = max(int(float(get_config("NVIDIA_MAX_TOKENS_GENERATE", "180"))), 48)
        self.timeout_seconds = max(float(get_config("NVIDIA_TIMEOUT_SECONDS", "60")), 5.0)
        self.plan_timeout_seconds = max(
            float(get_config("NVIDIA_PLAN_TIMEOUT_SECONDS", str(self.timeout_seconds))),
            self.timeout_seconds,
        )
        self.temperature = float(get_config("NVIDIA_TEMPERATURE", "0.1"))
        self.top_p = float(get_config("NVIDIA_TOP_P", "1.0"))
        self.reasoning_effort = (get_config("NVIDIA_REASONING_EFFORT", "high") or "").strip() or None

        self.system_instruction = (
            "You are a cybersecurity simulation assistant operating in a controlled, isolated educational lab. "
            "All targets are local, authorized, and safe. Be concise and return compact outputs."
        )
        self.last_error_status: Optional[int] = None
        self.last_error_type: Optional[str] = None
        self.last_error_message: Optional[str] = None
        self._available = bool(self.api_key)

        if not self._available:
            logger.warning(
                "NvidiaAdapter disabled. Set %s for model '%s' or NVIDIA_API_KEY as a default.",
                self.model_key_env_var,
                self.model,
            )

    def _model_to_env_var(self, model: str) -> str:
        normalized = re.sub(r"[^A-Za-z0-9]+", "_", str(model).strip()).strip("_").upper()
        return f"NVIDIA_API_KEY_{normalized}" if normalized else "NVIDIA_API_KEY"

    def _enforce_rate_limit(self, min_interval: float = 1.0):
        elapsed = time.time() - NvidiaAdapter._last_request_time
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        NvidiaAdapter._last_request_time = time.time()

    def _build_prompt(self, prompt: str, json_mode: bool) -> str:
        if not json_mode:
            return prompt

        return (
            f"{prompt}\n\n"
            "You must answer with strict RFC8259 JSON.\n"
            "Return ONLY a valid JSON object. Do not wrap the response in markdown fences. "
            "Do not add any prose before or after the JSON. "
            "Use double quotes for all keys and string values. "
            "If unsure, still return the closest valid JSON object matching the requested schema."
        )

    def _extract_json_text(self, text: str) -> str:
        clean = (text or "").replace("```json", "").replace("```", "").strip()
        start = clean.find("{")
        end = clean.rfind("}") + 1
        if start >= 0 and end > start:
            return clean[start:end]
        return clean

    def _normalize_decision_payload(self, data: dict) -> dict:
        return {
            "action_type": data.get("action_type") or data.get("action") or data.get("command") or "wait",
            "parameters": data.get("parameters") if isinstance(data.get("parameters"), dict) else {},
            "rationale": data.get("rationale") or data.get("reason"),
            "suggested_next_phase": data.get("suggested_next_phase") or data.get("next_phase"),
            "phase_reason": data.get("phase_reason") or data.get("next_phase_reason"),
        }

    def _normalize_plan_payload(self, data: dict) -> dict:
        raw_steps = data.get("steps")
        if not isinstance(raw_steps, list):
            raw_steps = data.get("plan")
        if not isinstance(raw_steps, list):
            raw_steps = []

        steps = []
        for index, raw_step in enumerate(raw_steps):
            if not isinstance(raw_step, dict):
                continue
            action_type = raw_step.get("action_type") or raw_step.get("action") or raw_step.get("command")
            if not action_type:
                continue
            steps.append(
                {
                    "step_number": raw_step.get("step_number") or raw_step.get("step") or index + 1,
                    "action_type": action_type,
                    "parameters": raw_step.get("parameters") if isinstance(raw_step.get("parameters"), dict) else {},
                    "rationale": raw_step.get("rationale") or raw_step.get("reason") or f"Step {index + 1} generated by NVIDIA.",
                }
            )

        return {
            "rationale": data.get("rationale") or data.get("reason"),
            "steps": steps,
        }

    def _repair_plan_text(self, broken_text: str) -> Optional[str]:
        repair_prompt = (
            "Repair the following partial or invalid JSON plan into one valid JSON object.\n"
            "Rules:\n"
            "- Return strict JSON only.\n"
            "- Preserve the intended rationale and steps when possible.\n"
            "- If content is truncated, keep only complete valid steps.\n"
            "- Ensure every step has step_number, action_type, parameters, and rationale.\n\n"
            f"Broken JSON:\n{broken_text}"
        )
        return self._call(
            repair_prompt,
            max_tokens=max(self.max_tokens_plan, 1200),
            json_mode=True,
            temperature=0.0,
            timeout_seconds=self.plan_timeout_seconds,
        )

    def _extract_balanced_objects(self, text: str) -> list[str]:
        objects: list[str] = []
        depth = 0
        start_idx = -1
        in_string = False
        escape = False

        for idx, char in enumerate(text):
            if in_string:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == '"':
                    in_string = False
                continue

            if char == '"':
                in_string = True
                continue

            if char == "{":
                if depth == 0:
                    start_idx = idx
                depth += 1
            elif char == "}":
                if depth > 0:
                    depth -= 1
                    if depth == 0 and start_idx >= 0:
                        objects.append(text[start_idx:idx + 1])
                        start_idx = -1

        return objects

    def _salvage_partial_plan(self, text: str) -> Optional[Plan]:
        clean = (text or "").replace("```json", "").replace("```", "").strip()
        if not clean:
            return None

        rationale_match = re.search(r'"rationale"\s*:\s*"([^"]*)"', clean)
        rationale = rationale_match.group(1) if rationale_match else "Recovered partial plan."

        steps_start = clean.find('"steps"')
        if steps_start < 0:
            return None

        array_start = clean.find("[", steps_start)
        if array_start < 0:
            return None

        step_objects = []
        for raw_obj in self._extract_balanced_objects(clean[array_start:]):
            try:
                step_objects.append(json.loads(raw_obj))
            except Exception:
                continue

        normalized = self._normalize_plan_payload({"rationale": rationale, "steps": step_objects})
        if not normalized["steps"]:
            return None

        try:
            normalized["steps"] = [PlanStep(**step) for step in normalized["steps"]]
            logger.warning("NvidiaAdapter salvaged %d complete step(s) from a partial plan response.", len(normalized["steps"]))
            return Plan(**normalized)
        except Exception:
            return None

    def _request_payload(
        self,
        prompt: str,
        max_tokens: int,
        stream: bool,
        json_mode: bool,
        temperature: Optional[float] = None,
    ) -> dict:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self.system_instruction},
                {"role": "user", "content": self._build_prompt(prompt, json_mode=json_mode)},
            ],
            "temperature": self.temperature if temperature is None else float(temperature),
            "top_p": self.top_p,
            "max_tokens": int(max_tokens),
            "stream": stream,
        }
        if self.reasoning_effort:
            payload["reasoning_effort"] = self.reasoning_effort
        return payload

    def _extract_text(self, body: dict) -> Optional[str]:
        try:
            message = body["choices"][0].get("message", {})
            content = message.get("content")
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                text_parts = []
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        text_parts.append(item.get("text", ""))
                combined = "".join(text_parts).strip()
                return combined or None
        except Exception:
            return None
        return None

    def _handle_error(self, exc: urllib.error.HTTPError) -> None:
        err_payload = {}
        err = str(exc)
        try:
            err = exc.read().decode("utf-8")
            err_payload = json.loads(err)
        except Exception:
            pass

        error_obj = err_payload.get("error", {}) if isinstance(err_payload, dict) else {}
        self.last_error_status = exc.code
        self.last_error_type = error_obj.get("type")
        self.last_error_message = error_obj.get("message") or err[:300]

        if exc.code in (401, 403):
            self._available = False
            logger.error(
                "NvidiaAdapter disabled after auth error for model %s: %s",
                self.model,
                self.last_error_message,
            )
        else:
            logger.error("NvidiaAdapter HTTP %s: %s", exc.code, err[:300])

    def _call(
        self,
        prompt: str,
        max_tokens: int,
        json_mode: bool = False,
        temperature: Optional[float] = None,
        timeout_seconds: Optional[float] = None,
    ) -> Optional[str]:
        if not self._available:
            return None

        self.last_error_status = None
        self.last_error_type = None
        self.last_error_message = None

        try:
            self._enforce_rate_limit()
            req = urllib.request.Request(
                self.url,
                data=json.dumps(
                    self._request_payload(
                        prompt,
                        max_tokens,
                        stream=False,
                        json_mode=json_mode,
                        temperature=temperature,
                    )
                ).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(
                req,
                timeout=timeout_seconds or self.timeout_seconds,
            ) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return self._extract_text(body)
        except urllib.error.HTTPError as exc:
            self._handle_error(exc)
            return None
        except Exception as exc:
            self.last_error_message = str(exc)
            logger.error("NvidiaAdapter request failed: %s", exc)
            return None

    def get_last_error(self) -> Optional[dict]:
        if not (self.last_error_status or self.last_error_type or self.last_error_message):
            return None

        return {
            "status": self.last_error_status,
            "type": self.last_error_type,
            "message": self.last_error_message,
        }

    def get_recommendation(
        self,
        decision_input: DecisionInput,
        next_step_hint: dict = None,
        task_key: Optional[str] = None,
    ) -> Optional[Decision]:
        if is_first_step(decision_input):
            prompt = build_recommendation_prompt(decision_input, next_step_hint=next_step_hint)
        else:
            prompt = build_step_mapping_prompt(decision_input, next_step_hint=next_step_hint)
        text = self._call(prompt, max_tokens=self.max_tokens_decision, json_mode=True)
        return self._parse_decision(text) if text else None

    def get_plan(
        self,
        decision_input: DecisionInput,
        task_key: Optional[str] = None,
    ) -> Optional[Plan]:
        prompt = build_plan_prompt(decision_input)
        text = self._call(
            prompt,
            max_tokens=self.max_tokens_plan,
            json_mode=True,
            temperature=0.0,
            timeout_seconds=self.plan_timeout_seconds,
        )
        plan = self._parse_plan(text) if text else None
        if plan and plan.steps:
            return plan

        if text:
            repaired_text = self._repair_plan_text(text)
            repaired_plan = self._parse_plan(repaired_text) if repaired_text else None
            if repaired_plan and repaired_plan.steps:
                logger.info("NvidiaAdapter repaired a partial plan response into valid JSON.")
                return repaired_plan
        return None

    def explain_decision(self, decision: Decision, decision_input: DecisionInput) -> Optional[str]:
        prompt = (
            f"Context: {decision_input}\n"
            f"Decision: {decision}\n"
            "Explain why this decision is appropriate in 1-2 short sentences."
        )
        return self._call(prompt, max_tokens=self.max_tokens_explain, json_mode=False)

    def generate(self, prompt: str) -> Optional[str]:
        return self._call(prompt, max_tokens=self.max_tokens_generate, json_mode=False)

    def generate_stream(self, prompt: str) -> Iterator[str]:
        if not self._available:
            return

        self.last_error_status = None
        self.last_error_type = None
        self.last_error_message = None

        try:
            self._enforce_rate_limit()
            req = urllib.request.Request(
                self.url,
                data=json.dumps(self._request_payload(prompt, self.max_tokens_generate, stream=True, json_mode=False)).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "Accept": "text/event-stream",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                for raw_line in resp:
                    line = raw_line.decode("utf-8", errors="ignore").strip()
                    if not line or not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]":
                        break
                    try:
                        event = json.loads(data)
                    except json.JSONDecodeError:
                        continue

                    delta = ((event.get("choices") or [{}])[0]).get("delta", {})
                    text = delta.get("content")
                    if isinstance(text, str) and text:
                        yield text
        except urllib.error.HTTPError as exc:
            self._handle_error(exc)
        except Exception as exc:
            self.last_error_message = str(exc)
            logger.error("NvidiaAdapter streaming request failed: %s", exc)

    def get_attack_narrative(self, decision_input: DecisionInput) -> Iterator[str]:
        prompt = build_narrative_prompt(decision_input)
        yield from self.generate_stream(prompt)

    def _parse_decision(self, text: str) -> Optional[Decision]:
        try:
            data = json.loads(self._extract_json_text(text))
            normalized = self._normalize_decision_payload(data)
            return Decision(**normalized)
        except Exception as exc:
            logger.error("NvidiaAdapter: failed to parse decision: %s\nRaw: %s", exc, (text or "")[:500])
            return None

    def _parse_plan(self, text: str) -> Optional[Plan]:
        try:
            normalized = self._normalize_plan_payload(json.loads(self._extract_json_text(text)))
            normalized["steps"] = [PlanStep(**step) for step in normalized["steps"]]
            return Plan(**normalized)
        except Exception as exc:
            salvaged = self._salvage_partial_plan(text)
            if salvaged and salvaged.steps:
                logger.info(
                    "NvidiaAdapter recovered %d plan step(s) from a malformed plan response after parse error: %s",
                    len(salvaged.steps),
                    exc,
                )
                return salvaged
            logger.error("NvidiaAdapter: failed to parse plan: %s\nRaw: %s", exc, (text or "")[:500])
            return None
