"""
Groq Adapter Module.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Iterator, Optional

from ai.llm.base import BaseLLMAdapter
from ai.schemas import Decision, DecisionInput, Plan, DecisionRequest

logger = logging.getLogger(__name__)


class GroqAdapter(BaseLLMAdapter):
    """
    Adapter for Groq API (Llama 3, Mixtral, etc.).
    """

    def __init__(self, model: str = "llama3-70b-8192"):
        self.api_key = os.getenv("GROQ_API_KEY")
        self.model = model
        self._client = None

        if self.api_key:
            try:
                from groq import Groq
                self._client = Groq(api_key=self.api_key)
            except ImportError:
                logger.warning("Groq SDK not installed. Install with `pip install groq`.")
            except Exception as e:
                logger.error(f"Failed to initialize Groq client: {e}")
        else:
            logger.warning("GROQ_API_KEY not set.")

    def get_recommendation(self, request: DecisionRequest) -> Optional[Decision]:
        if not self._client:
            return None
        
        # Simplified prompt construction
        prompt = (
            f"You are an autonomous red team operator.\n"
            f"Context: {json.dumps(request.context, default=str) if request.context else '{}'}\n"
            f"State: {request.decision_input}\n"
            "Recommend the next action. Return a JSON object with keys: 'action_type', 'parameters', and 'rationale'."
        )
        
        response = self.generate(prompt)
        if response:
            try:
                # Extract JSON if wrapped in markdown
                if "```" in response:
                    import re
                    match = re.search(r'```(?:json)?\s*(.*?)\s*```', response, re.DOTALL)
                    if match:
                        response = match.group(1)
                
                data = json.loads(response)
                return Decision(
                    action_type=data.get("action_type", "wait"),
                    parameters=data.get("parameters", {}),
                    rationale=data.get("rationale", "AI Decision")
                )
            except Exception as e:
                logger.error(f"Failed to parse Groq decision: {e}")
        return None

    def get_plan(self, decision_input: DecisionInput) -> Optional[Plan]:
        # Placeholder for plan generation
        return None

    def explain_decision(self, decision: Decision, decision_input: DecisionInput) -> Optional[str]:
        return decision.rationale

    def generate(self, prompt: str) -> Optional[str]:
        if not self._client:
            return None
        try:
            chat_completion = self._client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model=self.model,
                temperature=0.1,
            )
            return chat_completion.choices[0].message.content
        except Exception as e:
            logger.error(f"Groq generation error: {e}")
            return None

    def generate_stream(self, prompt: str) -> Iterator[str]:
        if not self._client:
            return
        # Stream implementation omitted for brevity, falling back to non-stream
        res = self.generate(prompt)
        if res:
            yield res

    def get_attack_narrative(self, decision_input: DecisionInput) -> Iterator[str]:
        prompt = f"Provide a tactical narrative for the current attack state: {decision_input}"
        yield from self.generate_stream(prompt)