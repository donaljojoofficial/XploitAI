from unittest.mock import patch

from django.test import SimpleTestCase

from ai.decision_engine import DecisionEngine
from ai.llm.base import BaseLLMAdapter
from ai.llm.task_router import TaskRouterAdapter


class _StubAdapter(BaseLLMAdapter):
    def __init__(self, name: str, available_attr: str):
        self.name = name
        setattr(self, available_attr, True)


class _GeminiStub(_StubAdapter):
    def __init__(self):
        super().__init__("gemini", "_client")


class _GroqStub(_StubAdapter):
    def __init__(self):
        super().__init__("groq", "_client")


class _OpenAIStub(_StubAdapter):
    def __init__(self):
        super().__init__("openai", "_available")


class _NvidiaStub(_StubAdapter):
    def __init__(self):
        super().__init__("nvidia", "_available")


class _LMStudioStub(_StubAdapter):
    def __init__(self):
        super().__init__("lmstudio", "_available")


class DecisionEngineProviderTests(SimpleTestCase):
    def test_specific_provider_only_initializes_requested_adapter(self):
        with patch("ai.decision_engine.GEMINI_AVAILABLE", True), \
             patch("ai.decision_engine.GROQ_AVAILABLE", True), \
             patch("ai.decision_engine.OPENAI_AVAILABLE", True), \
             patch("ai.decision_engine.NVIDIA_AVAILABLE", True), \
             patch("ai.decision_engine.LMSTUDIO_AVAILABLE", True), \
             patch("ai.decision_engine.GeminiAdapter", _GeminiStub), \
             patch("ai.decision_engine.GroqAdapter", _GroqStub), \
             patch("ai.decision_engine.OpenAIAdapter", _OpenAIStub), \
             patch("ai.decision_engine.NvidiaAdapter", _NvidiaStub), \
             patch("ai.decision_engine.LMStudioAdapter", _LMStudioStub):
            engine = DecisionEngine(provider="nvidia")

        self.assertIsInstance(engine.llm_adapter, TaskRouterAdapter)
        self.assertIn("nvidia", engine.llm_adapter.adapters_by_name)
        self.assertIn("local", engine.llm_adapter.adapters_by_name)
        self.assertNotIn("gemini", engine.llm_adapter.adapters_by_name)
        self.assertNotIn("groq", engine.llm_adapter.adapters_by_name)
        self.assertNotIn("lmstudio", engine.llm_adapter.adapters_by_name)

    def test_hybrid_only_initializes_nvidia_and_groq(self):
        with patch("ai.decision_engine.GEMINI_AVAILABLE", True), \
             patch("ai.decision_engine.GROQ_AVAILABLE", True), \
             patch("ai.decision_engine.OPENAI_AVAILABLE", True), \
             patch("ai.decision_engine.NVIDIA_AVAILABLE", True), \
             patch("ai.decision_engine.LMSTUDIO_AVAILABLE", True), \
             patch("ai.decision_engine.GeminiAdapter", _GeminiStub), \
             patch("ai.decision_engine.GroqAdapter", _GroqStub), \
             patch("ai.decision_engine.OpenAIAdapter", _OpenAIStub), \
             patch("ai.decision_engine.NvidiaAdapter", _NvidiaStub), \
             patch("ai.decision_engine.LMStudioAdapter", _LMStudioStub):
            engine = DecisionEngine(provider="hybrid")

        self.assertIsInstance(engine.llm_adapter, TaskRouterAdapter)
        self.assertIn("nvidia", engine.llm_adapter.adapters_by_name)
        self.assertIn("groq", engine.llm_adapter.adapters_by_name)
        self.assertIn("local", engine.llm_adapter.adapters_by_name)
        self.assertNotIn("gemini", engine.llm_adapter.adapters_by_name)
        self.assertNotIn("openai", engine.llm_adapter.adapters_by_name)
        self.assertNotIn("lmstudio", engine.llm_adapter.adapters_by_name)
