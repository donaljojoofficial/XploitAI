from django.test import SimpleTestCase

from ai.llm.prompts import build_recommendation_prompt, build_step_mapping_prompt
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
