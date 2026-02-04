"""
LLM Adapter Module.

This package contains adapters for external Large Language Models (LLMs).
These adapters serve as optional advisors to the decision engine.
"""
from .base import BaseLLMAdapter

__all__ = ["BaseLLMAdapter"]