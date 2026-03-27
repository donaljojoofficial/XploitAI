from django.test import SimpleTestCase

from ai.llm.base import BaseLLMAdapter
from ai.llm.task_router import TaskRouterAdapter
from ai.planner import AIPlanner
from ai.schemas import Decision, DecisionInput


class RecordingAdapter(BaseLLMAdapter):
    def __init__(self, name: str):
        self.name = name
        self.last_task_key = None

    def get_recommendation(self, decision_input, next_step_hint=None, task_key=None):
        self.last_task_key = task_key
        return Decision(
            action_type=self.name,
            parameters={},
            rationale=f"selected by {self.name}",
        )

    def get_plan(self, decision_input, task_key=None):
        self.last_task_key = task_key
        return None

    def explain_decision(self, decision, decision_input):
        return self.name

    def generate(self, prompt):
        return self.name

    def generate_stream(self, prompt):
        yield self.name

    def get_attack_narrative(self, decision_input):
        yield self.name


class TaskRouterAdapterTests(SimpleTestCase):
    def test_exact_route_overrides_generic_route(self):
        recon_adapter = RecordingAdapter("groq")
        generic_adapter = RecordingAdapter("openai")

        router = TaskRouterAdapter(
            adapters_by_name={
                "groq": recon_adapter,
                "openai": generic_adapter,
            },
            task_routes={
                "recommendation": ["openai", "groq"],
                "recommendation.reconnaissance": ["groq", "openai"],
            },
        )

        decision = router.get_recommendation(
            DecisionInput(
                phase="RECONNAISSANCE",
                known_services=[],
                past_actions=[],
                available_commands=[],
            ),
            task_key="recommendation.reconnaissance",
        )

        self.assertEqual(decision.action_type, "groq")
        self.assertEqual(recon_adapter.last_task_key, "recommendation.reconnaissance")

    def test_generic_route_is_used_when_exact_route_missing(self):
        generic_adapter = RecordingAdapter("openai")

        router = TaskRouterAdapter(
            adapters_by_name={"openai": generic_adapter},
            task_routes={"recommendation": ["openai"]},
        )

        decision = router.get_recommendation(
            DecisionInput(
                phase="ENUMERATION",
                known_services=[],
                past_actions=[],
                available_commands=[],
            ),
            task_key="recommendation.enumeration",
        )

        self.assertEqual(decision.action_type, "openai")
        self.assertEqual(generic_adapter.last_task_key, "recommendation.enumeration")


class AIPlannerTaskKeyTests(SimpleTestCase):
    def setUp(self):
        self.planner = AIPlanner.__new__(AIPlanner)

    def test_recommendation_task_key_uses_phase_for_success_path(self):
        decision_input = DecisionInput(
            phase="PRIVILEGE_ESCALATION",
            known_services=[],
            past_actions=[],
            available_commands=[],
        )

        self.assertEqual(
            self.planner._recommendation_task_key(decision_input),
            "recommendation.privilege_escalation",
        )

    def test_recommendation_task_key_uses_retry_bucket_after_failure(self):
        decision_input = DecisionInput(
            phase="EXPLOITATION",
            known_services=[],
            past_actions=[],
            available_commands=[],
            last_result=type(
                "LastResult",
                (),
                {"success": False, "output_summary": None, "raw_output": None, "error": None},
            )(),
        )

        self.assertEqual(
            self.planner._recommendation_task_key(decision_input),
            "recommendation.retry_failed_step",
        )

    def test_preferred_routes_put_selected_provider_first(self):
        routes = self.planner._preferred_routes("lmstudio")

        self.assertEqual(routes["plan.initial"][0], "lmstudio")
        self.assertEqual(routes["recommendation.exploitation"][0], "lmstudio")

    def test_resolve_proposed_command_name_maps_legacy_aliases(self):
        available_commands = [
            type("Command", (), {"name": "EndpointDiscovery"})(),
            type("Command", (), {"name": "ParameterDiscovery"})(),
        ]

        self.assertEqual(
            self.planner._resolve_proposed_command_name("ServiceDiscovery", available_commands),
            "EndpointDiscovery",
        )

        self.assertEqual(
            self.planner._resolve_proposed_command_name("ServiceScan", available_commands),
            "EndpointDiscovery",
        )

    def test_resolve_proposed_command_name_handles_case_and_spacing(self):
        available_commands = [
            type("Command", (), {"name": "HTTPHeaderFetch"})(),
        ]

        self.assertEqual(
            self.planner._resolve_proposed_command_name("http header fetch", available_commands),
            "HTTPHeaderFetch",
        )
