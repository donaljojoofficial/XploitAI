from __future__ import annotations

import json
import logging
from typing import Optional

import requests

from core.config import get_config

logger = logging.getLogger(__name__)


class NvidiaOutputAnalysisAdapter:
    """OpenAI-compatible NVIDIA adapter dedicated to command output analysis."""

    def __init__(self):
        self.host = (get_config("OUTPUT_ANALYSIS_HOST") or get_config("NVIDIA_HOST") or "https://integrate.api.nvidia.com").rstrip("/")
        self.api_key = get_config("OUTPUT_ANALYSIS_API_KEY") or get_config("NVIDIA_API_KEY")
        self.model = (
            get_config("OUTPUT_ANALYSIS_MODEL")
            or "nvidia/nemotron-3-super-120b-a12b"
        )
        self.timeout_seconds = max(float(get_config("OUTPUT_ANALYSIS_TIMEOUT_SECONDS", "90")), 5.0)
        self.max_tokens = max(int(float(get_config("OUTPUT_ANALYSIS_MAX_TOKENS", "1800"))), 256)
        self.temperature = float(get_config("OUTPUT_ANALYSIS_TEMPERATURE", "0.1"))
        self.top_p = float(get_config("OUTPUT_ANALYSIS_TOP_P", "0.95"))
        self.reasoning_budget = max(int(float(get_config("OUTPUT_ANALYSIS_REASONING_BUDGET", "4096"))), 512)
        self.url = f"{self.host}/v1/chat/completions"
        self._available = bool(self.api_key)

        if not self._available:
            logger.warning("Output analysis adapter disabled: no API key configured.")

    def analyze(self, prompt: str) -> Optional[dict]:
        if not self._available:
            return None

        payload = self._build_payload(prompt, max_tokens=self.max_tokens)

        try:
            content = self._request_content(payload)
            if not content:
                return None
            return json.loads(self._extract_json_text(content))
        except Exception as exc:
            logger.warning("Output analysis request failed: %s", exc)
            return None

    def generate_text(self, prompt: str, max_tokens: Optional[int] = None) -> Optional[str]:
        if not self._available:
            return None

        payload = self._build_payload(prompt, max_tokens=max_tokens or self.max_tokens)
        try:
            content = self._request_content(payload)
            return (content or "").strip() or None
        except Exception as exc:
            logger.warning("Output analysis text generation failed: %s", exc)
            return None

    def _build_payload(self, prompt: str, max_tokens: int) -> dict:
        return {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self.temperature,
            "top_p": self.top_p,
            "max_tokens": max_tokens,
            "stream": False,
            "extra_body": {
                "chat_template_kwargs": {"enable_thinking": True},
                "reasoning_budget": self.reasoning_budget,
            },
        }

    def _request_content(self, payload: dict) -> Optional[str]:
        response = requests.post(
            self.url,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            json=payload,
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        data = response.json()
        content = ((data.get("choices") or [{}])[0].get("message") or {}).get("content")
        if isinstance(content, list):
            text_parts = [
                item.get("text", "")
                for item in content
                if isinstance(item, dict) and item.get("type") == "text"
            ]
            content = "".join(text_parts).strip()
        return content

    def _extract_json_text(self, text: str) -> str:
        clean = (text or "").replace("```json", "").replace("```", "").strip()
        start = clean.find("{")
        end = clean.rfind("}")
        if start >= 0 and end > start:
            return clean[start:end + 1]
        return clean
