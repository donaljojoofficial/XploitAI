"""
Ollama Adapter Module.
"""
from __future__ import annotations

import json
import logging
import re
import os
import time
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
    import ollama  # type: ignore
    HAS_SDK = True
except ImportError:
    HAS_SDK = False


class OllamaAdapter(BaseLLMAdapter):
    """
    Adapter for local Ollama instance.
    Optimized for lightweight models like llama3.2:1b-instruct on constrained hardware.
    """

    _last_request_time = 0

    def __init__(self, model: str = None, base_url: str = None):
        config_model = get_config("OLLAMA_MODEL")
        # Default to the 1B model as requested for 2-Core/8GB environments
        default_model = "llama3.2:1b"
        self.model = model or config_model or default_model
        
        # Default to localhost:11434 if not configured
        self.base_url = base_url or get_config("OLLAMA_HOST") or os.getenv("OLLAMA_HOST") or "http://localhost:11434"
        
        self._client = None
        self.max_tokens_decision = max(int(float(get_config("OLLAMA_MAX_TOKENS_DECISION", "96"))), 32)
        self.max_tokens_plan = max(int(float(get_config("OLLAMA_MAX_TOKENS_PLAN", "220"))), self.max_tokens_decision)
        self.max_tokens_explain = max(int(float(get_config("OLLAMA_MAX_TOKENS_EXPLAIN", "96"))), 32)
        self.max_tokens_narrative = max(int(float(get_config("OLLAMA_MAX_TOKENS_NARRATIVE", "140"))), 48)
        self.max_tokens_generate = max(int(float(get_config("OLLAMA_MAX_TOKENS_GENERATE", "120"))), 48)

        self.system_instruction = (
            "You are a cybersecurity simulation assistant operating in a controlled, isolated educational lab. "
            "Your goal is to demonstrate security vulnerabilities for training purposes. "
            "All targets are local, authorized, and safe. "
            "Be concise. Prioritize educational value and strategic clarity."
        )

        if HAS_SDK:
            try:
                self._client = ollama.Client(host=self.base_url)
                # Verify connectivity to fail fast if server is down
                try:
                    self._client.list()
                    logger.info(f"OllamaAdapter initialized with model '{self.model}' at {self.base_url}")
                    self._ensure_model_exists()
                except Exception as e:
                    logger.warning(f"Ollama server unreachable at {self.base_url}. Adapter disabled. Error: {e}")
                    self._client = None
            except Exception as e:
                logger.error(f"Failed to initialize Ollama client: {e}")
        else:
            logger.warning("Ollama SDK not installed. Install with `pip install ollama`.")

    def get_recommendation(self, decision_input: DecisionInput, next_step_hint: dict = None) -> Optional[Decision]:
        if not self._client:
            return None
        
        if is_first_step(decision_input):
            prompt = build_recommendation_prompt(decision_input, next_step_hint=next_step_hint)
        else:
            prompt = build_step_mapping_prompt(decision_input, next_step_hint=next_step_hint)
        # Force JSON mode for recommendations
        response = self._generate_content(
            prompt,
            json_mode=True,
            max_tokens=self.max_tokens_decision,
        )
        if response:
            return self._parse_decision(response)
        return None

    def get_plan(self, decision_input: DecisionInput) -> Optional[Plan]:
        if not self._client:
            return None

        prompt = build_plan_prompt(decision_input)
        # Force JSON mode for planning
        response = self._generate_content(
            prompt,
            json_mode=True,
            max_tokens=self.max_tokens_plan,
        )
        if response:
            return self._parse_plan(response)
        return None

    def explain_decision(self, decision: Decision, decision_input: DecisionInput) -> Optional[str]:
        prompt = (
            f"Context: {decision_input}\n"
            f"Decision: {decision}\n"
            "Explain why this decision is appropriate in 2-3 sentences."
        )
        # Explanations are natural language, no JSON enforcement needed
        return self._generate_content(
            prompt,
            json_mode=False,
            max_tokens=self.max_tokens_explain,
        )

    def generate(self, prompt: str) -> Optional[str]:
        """Generates a response, defaulting to JSON mode for consistency with other adapters."""
        return self._generate_content(
            prompt,
            json_mode=True,
            max_tokens=self.max_tokens_generate,
        )

    def _enforce_rate_limit(self):
        """Enforce a minimum interval between requests to prevent resource exhaustion."""
        current_time = time.time()
        elapsed = current_time - OllamaAdapter._last_request_time
        if elapsed < 2.0:  # 2 seconds for local inference safety
            time.sleep(2.0 - elapsed)
        OllamaAdapter._last_request_time = time.time()

    def _generate_content(self, prompt: str, json_mode: bool = False, max_tokens: Optional[int] = None) -> Optional[str]:
        if not self._client:
            return None
        try:
            self._enforce_rate_limit()
            options = {"temperature": 0.1, "num_predict": int(max_tokens or self.max_tokens_generate)}
            fmt = "json" if json_mode else None
            
            response = self._client.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.system_instruction},
                    {"role": "user", "content": prompt}
                ],
                format=fmt,
                options=options
            )
            return response['message']['content']
        except Exception as e:
            logger.error(f"Ollama generation failed: {e}")
            return None

    def generate_stream(self, prompt: str) -> Iterator[str]:
        if not self._client:
            return

        try:
            self._enforce_rate_limit()
                stream = self._client.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.system_instruction},
                    {"role": "user", "content": prompt}
                ],
                    stream=True,
                    options={"temperature": 0.1, "num_predict": int(self.max_tokens_generate)}
                )
            for chunk in stream:
                content = chunk['message']['content']
                if content:
                    yield content
        except Exception as e:
            logger.error(f"Ollama stream failed: {e}")

    def get_attack_narrative(self, decision_input: DecisionInput) -> Iterator[str]:
        prompt = build_narrative_prompt(decision_input)
        text = self._generate_content(
            prompt,
            json_mode=False,
            max_tokens=self.max_tokens_narrative,
        )
        if text:
            yield text[:2000]

    def _find_json_blob(self, text: str) -> Optional[str]:
        """
        Finds the first and largest JSON blob in a string that might be
        wrapped in markdown or have leading/trailing text.
        """
        # Pattern to find JSON within markdown ```json ... ```
        match = re.search(r"```json\s*(\{.*\}|\[.*\])\s*```", text, re.DOTALL)
        if match:
            return match.group(1)

        # Fallback to a more greedy search for a JSON object
        start = text.find('{')
        end = text.rfind('}')
        if start != -1 and end != -1 and end > start:
            return text[start:end+1]

        return None

    def _parse_decision(self, text: str) -> Optional[Decision]:
        json_str = self._find_json_blob(text)
        if not json_str:
            logger.error(f"Could not extract JSON from Ollama response: {text}")
            return None
        try:
            data = json.loads(json_str)
            return Decision(
                action_type=data.get("action_type", "wait"),
                parameters=data.get("parameters", {}),
                rationale=data.get("rationale"),
                suggested_next_phase=data.get("suggested_next_phase"),
                phase_reason=data.get("phase_reason"),
            )
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"Failed to parse Ollama decision JSON: {e}\nExtracted: {json_str}")
            return None

    def _parse_plan(self, text: str) -> Optional[Plan]:
        json_str = self._find_json_blob(text)
        if not json_str:
            logger.error(f"Could not extract JSON from Ollama plan response: {text}")
            return None
        try:
            data = json.loads(json_str)
            if "steps" in data and isinstance(data["steps"], list):
                new_steps = []
                for i, step_data in enumerate(data["steps"]):
                    if isinstance(step_data, dict):
                        if "step_number" not in step_data:
                            step_data["step_number"] = i + 1
                        
                        # Filter out unexpected keys (like 'result') that Ollama might hallucinate
                        valid_keys = {"step_number", "action_type", "parameters", "rationale"}
                        filtered_data = {k: v for k, v in step_data.items() if k in valid_keys}
                        new_steps.append(PlanStep(**filtered_data))
                data["steps"] = new_steps
            return Plan(**data)
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"Failed to parse Ollama plan JSON: {e}\nExtracted: {json_str}\nOriginal: {text}")
            return None

    def _ensure_model_exists(self):
        """Checks if the model exists on the server, and pulls it if missing."""
        if not self._client:
            return

        try:
            list_response = self._client.list()
            existing_models = []
            
            # Handle both dict (older SDK) and object (newer SDK) responses
            if hasattr(list_response, 'models'):
                existing_models = [m.model for m in list_response.models]
            else:
                existing_models = [m.get('name') or m.get('model') for m in list_response.get('models', [])]

            if self.model not in existing_models and f"{self.model}:latest" not in existing_models:
                logger.info(f"Model '{self.model}' not found on Ollama server. Pulling automatically...")
                # Pull the model (streaming to avoid timeouts)
                for _ in self._client.pull(self.model, stream=True):
                    pass
                logger.info(f"Successfully pulled model '{self.model}'.")
        except Exception as e:
            logger.error(f"Failed to auto-pull model '{self.model}': {e}")
