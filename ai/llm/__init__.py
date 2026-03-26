"""
LLM Adapter Module.

This package contains adapters for external Large Language Models (LLMs).
These adapters serve as optional advisors to the decision engine.
"""
from .base import BaseLLMAdapter
from .gemini import GeminiAdapter
from .groq_adapter import GroqAdapter
from .openai_adapter import OpenAIAdapter
from .lmstudio_adapter import LMStudioAdapter
from .local_rule_engine import LocalRuleEngine

__all__ = ["BaseLLMAdapter", "GeminiAdapter", "GroqAdapter", "OpenAIAdapter", "LMStudioAdapter", "LocalRuleEngine"]
