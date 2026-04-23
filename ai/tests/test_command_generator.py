from django.test import SimpleTestCase

from ai.command_generator import CommandGenerator
from ai.llm.local_rule_engine import LocalRuleEngine


class CommandGeneratorTests(SimpleTestCase):
    def test_rule_only_mode_skips_llm_router_initialization(self):
        generator = CommandGenerator(use_llm=False, llm_provider="auto")

        self.assertIsInstance(generator.llm_client, LocalRuleEngine)
