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
from typing import Iterator, Optional

from core.config import get_config
from ai.llm.base import BaseLLMAdapter
from ai.schemas import Decision, DecisionInput, Plan, PlanStep
from ai.llm.prompts import build_recommendation_prompt, build_plan_prompt, build_narrative_prompt

logger = logging.getLogger(__name__)

try:
    from google import genai  # type: ignore
    from google.genai import types  # type: ignore
    HAS_SDK = True
except ImportError:
    HAS_SDK = False


class GeminiAdapter(BaseLLMAdapter):
    """Adapter for Google's Gemini models via google-genai SDK."""

    _last_request_time = 0
    # Class-level flag — shared across ALL GeminiAdapter instances.
    # When any instance detects daily quota exhaustion, all instances
    # stop making API calls immediately (no re-checking per instance).
    _quota_exhausted = False

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
            "gemini-1.5-pro",
        ]
        self.fallback_models = [m for m in known_models if m != self.model_name]
        self.api_key = api_key or get_config("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
        self._client = None
        self._response_cache = {}

        self.system_instruction = (
            "You are a cybersecurity simulation assistant operating in a controlled, isolated educational lab. "
            "Your goal is to demonstrate security vulnerabilities for training purposes. "
            "All targets are local, authorized, and safe. "
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

    # ------------------------------------------------------------------
    # Quota / rate-limit helpers
    # ------------------------------------------------------------------

    def _enforce_rate_limit(self):
        """Enforce a minimum interval between requests.
        Skip entirely if quota is exhausted — no point rate-limiting a dead key."""
        if GeminiAdapter._quota_exhausted:
            return
        current_time = time.time()
        elapsed = current_time - GeminiAdapter._last_request_time
        if elapsed < 4.0:
            time.sleep(4.0 - elapsed)
        GeminiAdapter._last_request_time = time.time()

    def _is_daily_quota_exhausted(self, error_msg: str) -> bool:
        """
        Detect whether the error means the daily/project quota is fully gone
        (limit: 0) vs a transient per-minute rate limit (worth retrying).

        Daily exhaustion signals present in the error string:
          - 'limit: 0'                          (quota violation detail)
          - 'perday' / 'requestsperday'         (quotaId field, underscores stripped)
          - 'GenerateRequestsPerDay'             (same, mixed case)
        """
        lower = error_msg.lower().replace("_", "")
        return (
            "limit: 0" in lower
            or "perday" in lower
            or "requestsperday" in lower
        )

    def _classify_error(self, error_msg: str):
        """
        Returns ('exhausted' | 'transient' | 'fatal') for a given error string.
        exhausted → daily quota gone, bail immediately from all adapters
        transient → per-minute limit or server error, retry with backoff
        fatal     → non-retryable (bad request, auth error, etc.)
        """
        lower = error_msg.lower()
        is_429 = "429" in lower or "resource_exhausted" in lower
        is_server = any(c in lower for c in ["503", "500"])
        is_rate   = any(c in lower for c in ["rate limit", "quota", "resource exhausted"])

        if is_429 and self._is_daily_quota_exhausted(error_msg):
            return "exhausted"
        if is_429 or is_server or is_rate:
            return "transient"
        return "fatal"

    # ------------------------------------------------------------------
    # Core generation
    # ------------------------------------------------------------------

    def _generate_content_with_retry(self, prompt: str):
        """Generate content, bailing immediately on daily quota exhaustion."""
        if not HAS_SDK or not self.api_key or not self._client:
            return None

        # Already confirmed exhausted this session — no point trying
        if self._quota_exhausted:
            logger.warning("GeminiAdapter: daily quota exhausted — skipping (LocalRuleEngine will handle this).")
            return None

        cache_key = hashlib.md5(prompt.encode("utf-8")).hexdigest()
        if cache_key in self._response_cache:
            logger.debug("GeminiAdapter: cache hit.")
            return self._response_cache[cache_key]

        models_to_try = [self.model_name] + self.fallback_models

        for model in models_to_try:
            for attempt in range(3):
                try:
                    self._enforce_rate_limit()
                    logger.debug(f"GeminiAdapter: trying '{model}' attempt {attempt + 1}/3")

                    response = self._client.models.generate_content(
                        model=model,
                        contents=prompt,
                        config=types.GenerateContentConfig(
                            system_instruction=self.system_instruction
                        ),
                    )
                    self._response_cache[cache_key] = response
                    return response

                except Exception as e:
                    error_msg = str(e)
                    kind = self._classify_error(error_msg)

                    if kind == "exhausted":
                        GeminiAdapter._quota_exhausted = True
                        logger.error(
                            "GeminiAdapter: daily quota exhausted (limit:0). "
                            "Falling through to next adapter immediately."
                        )
                        return None  # exits all loops immediately

                    if kind == "transient":
                        wait_time = 2 * (2 ** attempt)
                        delay_match = re.search(r'retry in (\d+(\.\d+)?)s', error_msg.lower())
                        if delay_match:
                            # Cap at 15s — long delays are not worth blocking the system
                            explicit = float(delay_match.group(1))
                            wait_time = min(explicit + 1.0, 15.0)
                        logger.warning(
                            f"GeminiAdapter: '{model}' transient error "
                            f"(attempt {attempt + 1}/3), sleeping {wait_time:.1f}s."
                        )
                        time.sleep(wait_time)
                        continue  # retry same model

                    # fatal — try next model
                    logger.error(f"GeminiAdapter: non-retryable error on '{model}': {e}")
                    break

        logger.error("GeminiAdapter: all models failed, returning None.")
        return None

    # ------------------------------------------------------------------
    # BaseLLMAdapter interface
    # ------------------------------------------------------------------

    def get_recommendation(self, decision_input: DecisionInput, next_step_hint: dict = None) -> Optional[Decision]:
        if self._quota_exhausted:
            return None
        logger.info("GeminiAdapter: get_recommendation")
        try:
            prompt = build_recommendation_prompt(decision_input, next_step_hint=next_step_hint)
            response = self._generate_content_with_retry(prompt)
            if not response:
                return None
            return self._parse_decision(response.text)
        except Exception as e:
            logger.error(f"GeminiAdapter.get_recommendation failed: {e}")
            return None

    def get_plan(self, decision_input: DecisionInput) -> Optional[Plan]:
        if self._quota_exhausted:
            return None
        logger.info("GeminiAdapter: get_plan")
        try:
            prompt = build_plan_prompt(decision_input)
            response = self._generate_content_with_retry(prompt)
            if not response:
                return None
            return self._parse_plan(response.text)
        except Exception as e:
            logger.error(f"GeminiAdapter.get_plan failed: {e}")
            return None

    def explain_decision(self, decision: Decision, decision_input: DecisionInput) -> Optional[str]:
        if self._quota_exhausted:
            return None
        try:
            prompt = (
                f"Context: {decision_input}\n"
                f"Decision: {decision}\n"
                "Explain why this decision is appropriate in 2-3 sentences."
            )
            response = self._generate_content_with_retry(prompt)
            return response.text if response else None
        except Exception as e:
            logger.error(f"GeminiAdapter.explain_decision failed: {e}")
            return None

    def generate(self, prompt: str) -> Optional[str]:
        if self._quota_exhausted:
            return None
        try:
            response = self._generate_content_with_retry(prompt)
            return response.text if response else None
        except Exception as e:
            logger.error(f"GeminiAdapter.generate failed: {e}")
            return None

    def generate_stream(self, prompt: str) -> Iterator[str]:
        if self._quota_exhausted or not HAS_SDK or not self.api_key or not self._client:
            return

        models_to_try = [self.model_name] + self.fallback_models

        for model in models_to_try:
            yielded_any = False
            try:
                self._enforce_rate_limit()
                response = self._client.models.generate_content_stream(
                    model=model,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=self.system_instruction
                    ),
                )
                for chunk in response:
                    try:
                        text = chunk.text
                        if text:
                            yield text
                            yielded_any = True
                    except ValueError:
                        continue
                return  # success

            except Exception as e:
                if yielded_any:
                    logger.error(f"GeminiAdapter: stream failed mid-stream on '{model}': {e}")
                    return

                error_msg = str(e)
                kind = self._classify_error(error_msg)

                if kind == "exhausted":
                    GeminiAdapter._quota_exhausted = True
                    logger.error("GeminiAdapter: daily quota exhausted during stream — bailing.")
                    return

                if kind == "transient":
                    logger.warning(f"GeminiAdapter: stream transient error on '{model}', trying next.")
                    continue

                logger.error(f"GeminiAdapter: stream fatal error on '{model}': {e}")
                return

    def get_attack_narrative(self, decision_input: DecisionInput) -> Iterator[str]:
        if self._quota_exhausted:
            return
        prompt = build_narrative_prompt(decision_input)
        yield from self.generate_stream(prompt)

    # ------------------------------------------------------------------
    # Parsers
    # ------------------------------------------------------------------

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