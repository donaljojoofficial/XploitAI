from django.test import SimpleTestCase

from ai.llm.prompts import build_plan_prompt, build_recommendation_prompt, build_step_mapping_prompt
from ai.schemas import DecisionInput


class PromptActionFilteringTests(SimpleTestCase):
    def test_recommendation_prompt_uses_available_commands(self):
        decision_input = DecisionInput(
            phase="discovery",
            known_services=[],
            past_actions=[],
            available_commands=[
                {"id": 10, "name": "HTTPHeaderFetch", "description": "headers"},
                {"id": 11, "name": "ParameterDiscovery", "description": "params"},
            ],
        )

        prompt = build_recommendation_prompt(decision_input)

        self.assertIn("HTTPHeaderFetch, ParameterDiscovery", prompt)
        self.assertNotIn("PassiveRecon", prompt)

    def test_step_mapping_prompt_uses_available_commands(self):
        decision_input = DecisionInput(
            phase="discovery",
            known_services=[],
            past_actions=[],
            available_commands=[
                {"id": 11, "name": "ParameterDiscovery", "description": "params"},
            ],
        )

        prompt = build_step_mapping_prompt(decision_input)

        self.assertIn("ParameterDiscovery", prompt)
        self.assertNotIn("PassiveRecon", prompt)

    def test_plan_prompt_calls_out_payload_and_script_actions_when_available(self):
        decision_input = DecisionInput(
            phase="exploitation",
            known_services=[],
            past_actions=[],
            available_commands=[
                {"id": 21, "name": "ExploitAttempt", "description": "attempt"},
                {"id": 22, "name": "PayloadGeneration", "description": "payload"},
                {"id": 23, "name": "ExploitScriptGeneration", "description": "script"},
            ],
        )

        prompt = build_plan_prompt(decision_input)

        self.assertIn("Payload/Script-capable actions currently available", prompt)
        self.assertIn("PayloadGeneration", prompt)
        self.assertIn("ExploitScriptGeneration", prompt)
        self.assertIn('"stage_label"', prompt)
        self.assertIn('"execution_type"', prompt)
        self.assertIn('"script_content"', prompt)
