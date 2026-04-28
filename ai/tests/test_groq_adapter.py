from types import SimpleNamespace
from unittest.mock import Mock

from django.test import SimpleTestCase

from ai.llm.groq_adapter import GroqAdapter


class GroqAdapterRecoveryTests(SimpleTestCase):
    def test_generate_recovers_from_strict_json_token_failure(self):
        adapter = GroqAdapter.__new__(GroqAdapter)
        adapter._client = Mock()
        adapter._response_cache = {}
        adapter.model = "llama-3.1-8b-instant"
        adapter.fallback_models = []
        adapter.system_instruction = "You are a test adapter."
        adapter.max_tokens_generate = 120
        adapter._enforce_rate_limit = lambda: None

        strict_error = Exception(
            "Error code: 400 - {'error': {'message': 'Failed to generate JSON', "
            "'code': 'json_validate_failed', 'failed_generation': "
            "'max completion tokens reached before generating a valid document'}}"
        )
        recovered = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='```json {"action_type":"wait","parameters":{}} ```'))]
        )
        adapter._client.chat.completions.create.side_effect = [strict_error, recovered]

        text = adapter.generate("Return a decision", max_tokens=96, json_mode=True)

        self.assertEqual(text, '{"action_type":"wait","parameters":{}}')
        self.assertEqual(adapter._client.chat.completions.create.call_count, 2)

    def test_parse_plan_extracts_json_from_markdown_wrapper(self):
        adapter = GroqAdapter.__new__(GroqAdapter)

        plan = adapter._parse_plan(
            """```json
            {"rationale":"ok","steps":[{"action_type":"HTTPHeaderFetch","parameters":{},"rationale":"headers"}]}
            ```"""
        )

        self.assertIsNotNone(plan)
        self.assertEqual(plan.steps[0].action_type, "HTTPHeaderFetch")
        self.assertEqual(plan.steps[0].step_number, 1)
