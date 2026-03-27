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
import socket
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
        cfg_timeout = get_config("LMSTUDIO_TIMEOUT_SECONDS", "60")
        cfg_plan_timeout = get_config("LMSTUDIO_PLAN_TIMEOUT_SECONDS", "180")
        cfg_retries = get_config("LMSTUDIO_TIMEOUT_RETRIES", "1")
        cfg_cooldown = get_config("LMSTUDIO_RETRY_COOLDOWN_SECONDS", "30")
        cfg_decision_tokens = get_config("LMSTUDIO_MAX_TOKENS_DECISION", "96")
        cfg_plan_tokens = get_config("LMSTUDIO_MAX_TOKENS_PLAN", "220")
        cfg_explain_tokens = get_config("LMSTUDIO_MAX_TOKENS_EXPLAIN", "96")
        cfg_narrative_tokens = get_config("LMSTUDIO_MAX_TOKENS_NARRATIVE", "140")
        cfg_generate_tokens = get_config("LMSTUDIO_MAX_TOKENS_GENERATE", "120")

        self.host  = (host  or cfg_host  or "http://localhost:1234").rstrip("/")
        self.model = model or cfg_model or "phi-4-mini-instruct"
        self.url   = f"{self.host}/v1/chat/completions"
        self.request_timeout_seconds = max(float(cfg_timeout), 1.0)
        self.plan_timeout_seconds = max(float(cfg_plan_timeout), self.request_timeout_seconds)
        self.timeout_retries = max(int(float(cfg_retries)), 0)
        self.retry_cooldown_seconds = max(float(cfg_cooldown), 1.0)
        self.max_tokens_decision = max(int(float(cfg_decision_tokens)), 32)
        self.max_tokens_plan = max(int(float(cfg_plan_tokens)), self.max_tokens_decision)
        self.max_tokens_explain = max(int(float(cfg_explain_tokens)), 32)
        self.max_tokens_narrative = max(int(float(cfg_narrative_tokens)), 48)
        self.max_tokens_generate = max(int(float(cfg_generate_tokens)), 48)
        self._disabled_until = 0.0

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

    def _cooldown_active(self) -> bool:
        return time.time() < self._disabled_until

    def _mark_temporarily_unavailable(self, reason: str):
        self._available = False
        self._disabled_until = time.time() + self.retry_cooldown_seconds
        logger.warning(
            "LMStudioAdapter temporarily disabled for %.0fs: %s",
            self.retry_cooldown_seconds,
            reason,
        )

    # ------------------------------------------------------------------
    # Server health check
    # ------------------------------------------------------------------

    def _check_server(self) -> bool:
        """Ping /v1/models to confirm LM Studio is running."""
        if self._cooldown_active():
            return False
        try:
            req = urllib.request.Request(
                f"{self.host}/v1/models",
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(
                req, timeout=min(self.request_timeout_seconds, 3.0)
            ) as resp:
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

    def _call(
        self,
        messages: list,
        max_tokens: int = 1024,
        temperature: float = 0.1,
        stream: bool = False,
        timeout_seconds: Optional[float] = None,
        timeout_retries: Optional[int] = None,
    ) -> Optional[str]:
        """
        POST to /v1/chat/completions and return the assistant's text.
        Returns None on any error.
        """
        if self._cooldown_active():
            return None

        if not self._available:
            # Re-check once in case server was started after init
            self._available = self._check_server()
            if not self._available:
                return None

        base_timeout_seconds = max(float(timeout_seconds or self.request_timeout_seconds), 1.0)
        retries = self.timeout_retries if timeout_retries is None else max(int(timeout_retries), 0)

        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
        }

        for attempt in range(retries + 1):
            attempt_timeout = min(base_timeout_seconds * (1.0 + 0.5 * attempt), 300.0)
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
                with urllib.request.urlopen(
                    req, timeout=attempt_timeout
                ) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
                    self._available = True
                    return body["choices"][0]["message"]["content"]

            except urllib.error.HTTPError as e:
                logger.error(
                    "LMStudioAdapter HTTP %s: %s", e.code, e.read().decode()[:300]
                )
                break
            except (socket.timeout, TimeoutError) as e:
                # Timeout usually means model is still thinking; don't mark server unavailable.
                if attempt < retries:
                    backoff = min(2.0 * (attempt + 1), 6.0)
                    logger.warning(
                        "LMStudioAdapter timeout after %.1fs (attempt %d/%d). Retrying in %.1fs.",
                        attempt_timeout,
                        attempt + 1,
                        retries + 1,
                        backoff,
                    )
                    time.sleep(backoff)
                    continue
                logger.warning(
                    "LMStudioAdapter request timed out after %.1fs (no cooldown).",
                    attempt_timeout,
                )
                return None
            except urllib.error.URLError as e:
                self._mark_temporarily_unavailable(f"connection error: {e.reason}")
                break
            except (KeyError, IndexError, json.JSONDecodeError) as e:
                logger.error("LMStudioAdapter unexpected response format: %s", e)
                break
            except Exception as e:
                if "timed out" in str(e).lower():
                    if attempt < retries:
                        backoff = min(2.0 * (attempt + 1), 6.0)
                        logger.warning(
                            "LMStudioAdapter timeout after %.1fs (attempt %d/%d). Retrying in %.1fs.",
                            attempt_timeout,
                            attempt + 1,
                            retries + 1,
                            backoff,
                        )
                        time.sleep(backoff)
                        continue
                    logger.warning(
                        "LMStudioAdapter request timed out after %.1fs (no cooldown).",
                        attempt_timeout,
                    )
                    return None
                logger.error("LMStudioAdapter unexpected error: %s", e)
                break

        return None

    def _call_stream(self, messages: list) -> Iterator[str]:
        """
        Streaming POST to /v1/chat/completions using SSE (server-sent events).
        Falls back to a single non-streaming call if streaming fails.
        """
        if self._cooldown_active():
            return

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
            with urllib.request.urlopen(
                req, timeout=self.request_timeout_seconds
            ) as resp:
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
        except (socket.timeout, TimeoutError):
            logger.warning(
                "LMStudioAdapter stream timed out after %.1fs (no cooldown).",
                self.request_timeout_seconds,
            )
            text = self._call(
                messages,
                timeout_seconds=self.request_timeout_seconds,
                timeout_retries=max(self.timeout_retries, 1),
            )
            if text:
                yield text
        except Exception as e:
            if "timed out" in str(e).lower():
                logger.warning(
                    "LMStudioAdapter stream timed out after %.1fs (no cooldown).",
                    self.request_timeout_seconds,
                )
            else:
                logger.error("LMStudioAdapter stream error: %s", e)
            # Graceful fallback — yield full non-streamed response
            text = self._call(
                messages,
                timeout_seconds=self.request_timeout_seconds,
                timeout_retries=max(self.timeout_retries, 1),
            )
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
        self,
        decision_input: DecisionInput,
        next_step_hint: dict = None,
        task_key: Optional[str] = None,
    ) -> Optional[Decision]:
        logger.info("LMStudioAdapter: get_recommendation")
        if is_first_step(decision_input):
            prompt = build_recommendation_prompt(decision_input, next_step_hint=next_step_hint)
        else:
            prompt = build_step_mapping_prompt(decision_input, next_step_hint=next_step_hint)
        text = self._call(
            self._build_messages(prompt),
            max_tokens=self.max_tokens_decision,
        )
        return self._parse_decision(text) if text else None

    def get_plan(
        self,
        decision_input: DecisionInput,
        task_key: Optional[str] = None,
    ) -> Optional[Plan]:
        logger.info("LMStudioAdapter: get_plan")
        prompt = build_plan_prompt(decision_input)
        text = self._call(
            self._build_messages(prompt),
            max_tokens=self.max_tokens_plan,
            timeout_seconds=self.plan_timeout_seconds,
            timeout_retries=max(self.timeout_retries, 2),
        )
        return self._parse_plan(text) if text else None

    def explain_decision(
        self, decision: Decision, decision_input: DecisionInput
    ) -> Optional[str]:
        prompt = (
            f"Context: {decision_input}\n"
            f"Decision: {decision}\n"
            "Explain why this decision is appropriate in 2-3 sentences."
        )
        return self._call(
            self._build_messages(prompt),
            max_tokens=self.max_tokens_explain,
        )

    def generate(self, prompt: str) -> Optional[str]:
        return self._call(
            self._build_messages(prompt),
            max_tokens=self.max_tokens_generate,
        )

    def generate_stream(self, prompt: str) -> Iterator[str]:
        yield from self._call_stream(self._build_messages(prompt))

    def get_attack_narrative(self, decision_input: DecisionInput) -> Iterator[str]:
        prompt = build_narrative_prompt(decision_input)
        # Narratives are informational; keep compact for local models.
        text = self._call(
            self._build_messages(prompt),
            max_tokens=self.max_tokens_narrative,
            timeout_seconds=self.request_timeout_seconds,
            timeout_retries=max(self.timeout_retries, 1),
        )
        if text:
            yield text

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
