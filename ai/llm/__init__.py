"""
LLM Adapter Module.

This package contains adapters for external Large Language Models (LLMs).
These adapters serve as optional advisors to the decision engine.
"""
from .base import BaseLLMAdapter
from .gemini import GeminiAdapter

__all__ = ["BaseLLMAdapter", "GeminiAdapter"]