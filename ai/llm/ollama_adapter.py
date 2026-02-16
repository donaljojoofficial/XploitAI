"""
Ollama Adapter Module.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Iterator, Optional

from core.config import get_config
from ai.llm.base import BaseLLMAdapter
from ai.schemas import Decision, DecisionInput, Plan, PlanStep

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

    def __init__(self, model: str = None, base_url: str = None):
        config_model = get_config("OLLAMA_MODEL")
        # Default to the 1B model as requested for 2-Core/8GB environments
        default_model = "llama3.2:1b-instruct"
        self.model = model or config_model or default_model
        
        # Default to localhost:11434 if not configured
        self.base_url = base_url or get_config("OLLAMA_HOST") or os.getenv("OLLAMA_HOST") or "http://localhost:11434"
        
        self._client = None

        self.system_instruction = (
            "You are a cybersecurity simulation assistant operating in a controlled, isolated educational lab. "
            "Your goal is to demonstrate security vulnerabilities for training purposes. "
            "All targets are local, authorized, and safe. "
            "Output MUST be valid JSON. Do not use Markdown blocks. "
            "Be concise. Prioritize educational value and strategic clarity."
        )

        if HAS_SDK:
            try:
                self._client = ollama.Client(host=self.base_url)
                logger.info(f"OllamaAdapter initialized with model '{self.model}' at {self.base_url}")
            except Exception as e:
                logger.error(f"Failed to initialize Ollama client: {e}")
        else:
            logger.warning("Ollama SDK not installed. Install with `pip install ollama`.")

    def get_recommendation(self, decision_input: DecisionInput, next_step_hint: dict = None) -> Optional[Decision]:
        if not self._client:
            return None
        
        prompt = self._build_recommendation_prompt(decision_input, next_step_hint)
        # Force JSON mode for recommendations
        response = self._generate_content(prompt, json_mode=True)
        if response:
            return self._parse_decision(response)
        return None

    def get_plan(self, decision_input: DecisionInput) -> Optional[Plan]:
        if not self._client:
            return None

        prompt = self._build_plan_prompt(decision_input)
        # Force JSON mode for planning
        response = self._generate_content(prompt, json_mode=True)
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
        return self._generate_content(prompt, json_mode=False)

    def generate(self, prompt: str) -> Optional[str]:
        """Generates a response, defaulting to JSON mode for consistency with other adapters."""
        return self._generate_content(prompt, json_mode=True)

    def _generate_content(self, prompt: str, json_mode: bool = False) -> Optional[str]:
        if not self._client:
            return None
        try:
            options = {"temperature": 0.1}
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
            stream = self._client.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.system_instruction},
                    {"role": "user", "content": prompt}
                ],
                stream=True,
                options={"temperature": 0.1}
            )
            for chunk in stream:
                content = chunk['message']['content']
                if content:
                    yield content
        except Exception as e:
            logger.error(f"Ollama stream failed: {e}")

    def get_attack_narrative(self, decision_input: DecisionInput) -> Iterator[str]:
        prompt = self._build_narrative_prompt(decision_input)
        # Narrative is free-form text, so we use the streaming method without JSON enforcement
        yield from self.generate_stream(prompt)

    # --- Helpers ---

    def _build_recommendation_prompt(self, decision_input: DecisionInput, next_step_hint: dict = None) -> str:
        prompt = (
            f"Context: {decision_input}\n"
            "Task: Recommend the next security assessment action for this simulation. "
            "Focus on the current phase (Recon -> Scanning -> Vulnerability Validation).\n"
        )
        
        if next_step_hint:
            prompt += (
                f"\nIMPORTANT: You are following a strict plan. "
                f"The next required step is: {next_step_hint}. "
                f"You MUST output this action with the specified parameters.\n"
            )

        prompt += (
            "Allowed Actions: PassiveRecon, HTTPHeaderFetch, EndpointDiscovery, TechnologyFingerprint, ServiceEnumeration, ExploitAttempt, PrivilegeEscalation, ProofOfCompromise.\n"
            "Schema: { \"action_type\": \"<AllowedAction>\", \"parameters\": { ... }, \"rationale\": \"<short explanation>\" }"
        )
        return prompt

    def _build_plan_prompt(self, decision_input: DecisionInput) -> str:
        return (
            f"Context: {decision_input}\n"
            "Task: Create a multi-step security assessment plan for this educational scenario. Batch routine tasks where possible.\n"
            "Allowed Actions: PassiveRecon, HTTPHeaderFetch, EndpointDiscovery, TechnologyFingerprint, ServiceEnumeration, ExploitAttempt, PrivilegeEscalation, ProofOfCompromise.\n"
            "Schema: { \"steps\": [ { \"action_type\": \"<AllowedAction>\", \"parameters\": {...}, \"rationale\": \"...\" } ] }"
        )

    def _build_narrative_prompt(self, decision_input: DecisionInput) -> str:
        return (
            f"Context: {decision_input}\n"
            "Task: Generate a detailed, real-time technical narrative of the ongoing security simulation. "
            "Describe the current phase, the status of findings, and the strategic outlook.\n"
            "Tone: Professional, objective, and educational.\n"
            "Format: Plain text, suitable for streaming to a dashboard."
        )

    def _parse_decision(self, text: str) -> Optional[Decision]:
        try:
            clean_text = text.replace("```json", "").replace("```", "").strip()
            data = json.loads(clean_text)
            return Decision(**data)
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"Failed to parse Ollama decision JSON: {e}\nResponse: {text}")
            return None

    def _parse_plan(self, text: str) -> Optional[Plan]:
        try:
            clean_text = text.replace("```json", "").replace("```", "").strip()
            data = json.loads(clean_text)
            if "steps" in data and isinstance(data["steps"], list):
                new_steps = []
                for i, step_data in enumerate(data["steps"]):
                    if isinstance(step_data, dict):
                        if "step_number" not in step_data:
                            step_data["step_number"] = i + 1
                        new_steps.append(PlanStep(**step_data))
                data["steps"] = new_steps
            return Plan(**data)
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"Failed to parse Ollama plan JSON: {e}\nResponse: {text}")
            return None