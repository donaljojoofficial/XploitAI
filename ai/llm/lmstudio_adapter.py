"""
LM Studio LLM Adapter — XploitAI

LM Studio exposes a local OpenAI-compatible REST API.
No SDK required — uses plain HTTP (urllib) so there are zero extra dependencies.

Default endpoint : http://localhost:1234/v1/chat/completions
Default model    : phi-4-mini-instruct  (whatever is loaded in LM Studio)

To use:
  1. Open LM Studio → load your model → start the local server (port 1234).
  2. Set in ai_config.json:
       "DEFAULT_LLM_PROVIDER": "lmstudio"
       "LMSTUDIO_MODEL": "phi-4-mini-instruct"   ← must match LM Studio model identifier
       "LMSTUDIO_HOST": "http://localhost:1234"   ← optional, default shown
  3. Restart the Django server.

WSL note: if Django/executor runs in WSL and LM Studio runs on Windows,
replace localhost with your Windows host IP (same as base_url in config.yaml).
"""
from __future__ import annotations

import json
import logging
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


class LMStudioAdapter(BaseLLMAdapter):
    """
    Adapter for LM Studio's OpenAI-compatible local server.

    LM Studio accepts the same request format as OpenAI's /v1/chat/completions.
    The 'model' field in the request must match the identifier shown in
    LM Studio's model list (e.g. 'phi-4-mini-instruct').
    """

    _last_request_time: float = 0.0

    def __init__(self, model: str = None, host: str = None):
        cfg_host  = get_config("LMSTUDIO_HOST")
        cfg_model = get_config("LMSTUDIO_MODEL")

        self.host  = (host  or cfg_host  or "http://localhost:1234").rstrip("/")
        self.model = model or cfg_model or "phi-4-mini-instruct"
        self.url   = f"{self.host}/v1/chat/completions"

        self.system_instruction = (
            "You are a cybersecurity simulation assistant operating in a controlled, "
            "isolated educational lab. Your goal is to demonstrate security vulnerabilities "
            "for training purposes. All targets are local, authorized, and safe. "
            "Be concise. Prioritize educational value and strategic clarity."
        )

        # Verify the server is reachable at startup
        self._available = self._check_server()
        if self._available:
            logger.info(
                "LMStudioAdapter ready — model '%s' at %s", self.model, self.host
            )
        else:
            logger.warning(
                "LMStudioAdapter: server at %s is not reachable. "
                "Start the LM Studio local server (port 1234) and reload.",
                self.host,
            )

    # ------------------------------------------------------------------
    # Server health check
    # ------------------------------------------------------------------

    def _check_server(self) -> bool:
        """Ping /v1/models to confirm LM Studio is running."""
        try:
            req = urllib.request.Request(
                f"{self.host}/v1/models",
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Rate limiting (light — local model, but avoids hammering it)
    # ------------------------------------------------------------------

    def _enforce_rate_limit(self, min_interval: float = 1.0):
        elapsed = time.time() - LMStudioAdapter._last_request_time
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        LMStudioAdapter._last_request_time = time.time()

    # ------------------------------------------------------------------
    # Core HTTP call
    # ------------------------------------------------------------------

    def _call(self, messages: list, max_tokens: int = 1024,
               temperature: float = 0.1, stream: bool = False) -> Optional[str]:
        """
        POST to /v1/chat/completions and return the assistant's text.
        Returns None on any error.
        """
        if not self._available:
            # Re-check once in case server was started after init
            self._available = self._check_server()
            if not self._available:
                return None

        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
        }

        try:
            self._enforce_rate_limit()
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return body["choices"][0]["message"]["content"]

        except urllib.error.HTTPError as e:
            logger.error(
                "LMStudioAdapter HTTP %s: %s", e.code, e.read().decode()[:300]
            )
        except urllib.error.URLError as e:
            logger.error("LMStudioAdapter connection error: %s", e.reason)
            self._available = False   # Stop hammering a dead server
        except (KeyError, IndexError, json.JSONDecodeError) as e:
            logger.error("LMStudioAdapter unexpected response format: %s", e)
        except Exception as e:
            logger.error("LMStudioAdapter unexpected error: %s", e)

        return None

    def _call_stream(self, messages: list) -> Iterator[str]:
        """
        Streaming POST to /v1/chat/completions using SSE (server-sent events).
        Falls back to a single non-streaming call if streaming fails.
        """
        if not self._available:
            self._available = self._check_server()
            if not self._available:
                return

        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": 1024,
            "temperature": 0.1,
            "stream": True,
        }

        try:
            self._enforce_rate_limit()
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "text/event-stream",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                for raw_line in resp:
                    line = raw_line.decode("utf-8").strip()
                    if not line.startswith("data:"):
                        continue
                    chunk_str = line[len("data:"):].strip()
                    if chunk_str == "[DONE]":
                        break
                    try:
                        chunk = json.loads(chunk_str)
                        delta = chunk["choices"][0].get("delta", {})
                        text = delta.get("content", "")
                        if text:
                            yield text
                    except (json.JSONDecodeError, KeyError, IndexError):
                        continue

        except Exception as e:
            logger.error("LMStudioAdapter stream error: %s", e)
            # Graceful fallback — yield full non-streamed response
            text = self._call(messages)
            if text:
                yield text

    # ------------------------------------------------------------------
    # Prompt builder helper
    # ------------------------------------------------------------------

    def _build_messages(self, prompt: str) -> list:
        return [
            {"role": "system", "content": self.system_instruction},
            {"role": "user",   "content": prompt},
        ]

    # ------------------------------------------------------------------
    # BaseLLMAdapter interface
    # ------------------------------------------------------------------

    def get_recommendation(
        self, decision_input: DecisionInput, next_step_hint: dict = None
    ) -> Optional[Decision]:
        logger.info("LMStudioAdapter: get_recommendation")
        if is_first_step(decision_input):
            prompt = build_recommendation_prompt(decision_input, next_step_hint)
        else:
            prompt = build_step_mapping_prompt(decision_input, next_step_hint)
        text = self._call(self._build_messages(prompt))
        return self._parse_decision(text) if text else None

    def get_plan(self, decision_input: DecisionInput) -> Optional[Plan]:
        logger.info("LMStudioAdapter: get_plan")
        prompt = build_plan_prompt(decision_input)
        text = self._call(self._build_messages(prompt))
        return self._parse_plan(text) if text else None

    def explain_decision(
        self, decision: Decision, decision_input: DecisionInput
    ) -> Optional[str]:
        prompt = (
            f"Context: {decision_input}\n"
            f"Decision: {decision}\n"
            "Explain why this decision is appropriate in 2-3 sentences."
        )
        return self._call(self._build_messages(prompt))

    def generate(self, prompt: str) -> Optional[str]:
        return self._call(self._build_messages(prompt))

    def generate_stream(self, prompt: str) -> Iterator[str]:
        yield from self._call_stream(self._build_messages(prompt))

    def get_attack_narrative(self, decision_input: DecisionInput) -> Iterator[str]:
        prompt = build_narrative_prompt(decision_input)
        yield from self._call_stream(self._build_messages(prompt))

    # ------------------------------------------------------------------
    # Parsers  (identical pattern to all other adapters)
    # ------------------------------------------------------------------

    def _parse_decision(self, text: str) -> Optional[Decision]:
        try:
            clean = text.replace("```json", "").replace("```", "").strip()
            start = clean.find("{")
            end   = clean.rfind("}") + 1
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
        except Exception as e:
            logger.error("LMStudioAdapter: failed to parse decision: %s\nRaw: %s", e, text[:300])
            return None

    def _parse_plan(self, text: str) -> Optional[Plan]:
        try:
            clean = text.replace("```json", "").replace("```", "").strip()
            start = clean.find("{")
            end   = clean.rfind("}") + 1
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
        except Exception as e:
            logger.error("LMStudioAdapter: failed to parse plan: %s\nRaw: %s", e, text[:300])
            return None