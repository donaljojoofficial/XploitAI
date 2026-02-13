"""
Base interface for LLM adapters in XploitAI.

Responsibility:
 - Defines the contract for external LLM providers (Gemini, Claude, Groq).
- Ensures all LLM interactions conform to internal data schemas.
- Enforces the "Advisory Only" nature of LLMs in this system.

Design Principles:
- Fail-safe: Methods return Optional results. If the LLM fails, returns garbage,
  or times out, the system must fall back to rule-based logic.
- Stateless: The adapter does not manage conversation history; context is passed in.
- Schema-driven: Inputs and outputs are strictly typed using ai.schemas.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterator, Optional

from ai.schemas import Decision, DecisionInput, Plan


class BaseLLMAdapter(ABC):
    """
    Abstract interface for Large Language Model (LLM) providers.

    This adapter layer isolates the core XploitAI system from specific LLM APIs
    (Gemini, Claude, Groq). It enforces a strict schema-in/schema-out contract,
    ensuring that LLM outputs are validated and structured before being used.

    Role in Architecture:
    - Advisory: The LLM suggests actions; it does not execute them.
    - Unreliable: Implementations must handle failures gracefully (return None).
    - Stateless: Each request provides full context; no session state is assumed.
    """

    @abstractmethod
    def get_recommendation(self, decision_input: DecisionInput, next_step_hint: dict = None) -> Optional[Decision]:
        """
        Request a single atomic action recommendation from the LLM.

        This method should:
        1. Construct a prompt based on the provided `decision_input`.
        2. Call the LLM API.
        3. Parse the response into a `Decision` object.
        4. Return None if the API fails, times out, or returns invalid JSON.

        Args:
            decision_input: Structured observation of the current attack state.
            next_step_hint: Optional dictionary containing the next required plan step to guide the AI.

        Returns:
            A valid Decision object or None.
        """
        ...

    @abstractmethod
    def get_plan(self, decision_input: DecisionInput) -> Optional[Plan]:
        """
        Request a multi-step attack plan from the LLM.

        Args:
            decision_input: Structured observation of the current attack state.

        Returns:
            A valid Plan object or None.
        """
        ...

    @abstractmethod
    def explain_decision(
        self, decision: Decision, decision_input: DecisionInput
    ) -> Optional[str]:
        """
        Generate a natural language explanation for a specific decision.

        This can be used to explain both LLM-generated and rule-based decisions.

        Args:
            decision: The decision to explain.
            decision_input: The context used to make the decision.

        Returns:
            A string explanation or None if generation fails.
        """
        ...

    @abstractmethod
    def generate(self, prompt: str) -> Optional[str]:
        """
        Generate raw text response for a given prompt.

        Args:
            prompt: The input prompt string.

        Returns:
            A string response or None if generation fails.
        """
        ...

    @abstractmethod
    def generate_stream(self, prompt: str) -> Iterator[str]:
        """
        Generate a streaming text response for a given prompt.

        Args:
            prompt: The input prompt string.

        Yields:
            String chunks of the generated response.
        """
        ...

    @abstractmethod
    def get_attack_narrative(self, decision_input: DecisionInput) -> Iterator[str]:
        """
        Generate a streaming narrative of the attack based on the current input.

        Args:
            decision_input: Structured observation of the current attack state.

        Yields:
            String chunks of the narrative.
        """
        ...