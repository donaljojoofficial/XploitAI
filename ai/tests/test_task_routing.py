from django.test import SimpleTestCase, TestCase

from ai.llm.base import BaseLLMAdapter
from ai.llm.nvidia_adapter import NvidiaAdapter
from ai.llm.task_router import TaskRouterAdapter
from ai.planner import AIPlanner
from ai.schemas import Decision, DecisionInput, Plan, PlanStep
from core.models import AttackState, Command, ExecutionResult, Phase


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


class PlanRecordingAdapter(RecordingAdapter):
    def __init__(self, step_names):
        super().__init__("planner")
        self.step_names = step_names
        self.last_plan_input = None

    def get_plan(self, decision_input, task_key=None):
        self.last_task_key = task_key
        self.last_plan_input = decision_input
        return Plan(
            rationale="phase plan",
            steps=[
                PlanStep(
                    step_number=index + 1,
                    action_type=name,
                    parameters={},
                    rationale=f"step {index + 1}",
                )
                for index, name in enumerate(self.step_names)
            ],
        )


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

    def test_ai_only_adapters_excludes_local_rule_engine(self):
        adapters = {
            "groq": RecordingAdapter("groq"),
            "local": RecordingAdapter("local"),
        }

        filtered = self.planner._ai_only_adapters(adapters)

        self.assertIn("groq", filtered)
        self.assertNotIn("local", filtered)

    def test_plan_adapter_is_none_for_local_provider(self):
        self.planner._discover_adapters = lambda: {"local": RecordingAdapter("local")}

        self.assertIsNone(self.planner._get_plan_adapter("local"))

    def test_plan_adapter_for_auto_uses_only_ai_providers(self):
        self.planner._discover_adapters = lambda: {
            "groq": RecordingAdapter("groq"),
            "local": RecordingAdapter("local"),
        }

        adapter = self.planner._get_plan_adapter("auto")

        self.assertIsInstance(adapter, TaskRouterAdapter)
        self.assertIn("groq", adapter.adapters_by_name)
        self.assertNotIn("local", adapter.adapters_by_name)

    def test_plan_adapter_for_hybrid_builds_ai_only_router(self):
        self.planner._discover_adapters = lambda: {
            "nvidia": RecordingAdapter("nvidia"),
            "groq": RecordingAdapter("groq"),
            "local": RecordingAdapter("local"),
        }

        adapter = self.planner._get_plan_adapter("hybrid")

        self.assertIsInstance(adapter, TaskRouterAdapter)
        self.assertIn("nvidia", adapter.adapters_by_name)
        self.assertIn("groq", adapter.adapters_by_name)
        self.assertNotIn("local", adapter.adapters_by_name)
        self.assertEqual(adapter.task_routes["plan.initial"][0], "nvidia")
        self.assertEqual(adapter.task_routes["plan.initial"][1], "groq")

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


class NvidiaAdapterPlanParsingTests(SimpleTestCase):
    def setUp(self):
        self.adapter = NvidiaAdapter.__new__(NvidiaAdapter)

    def test_parse_plan_salvages_truncated_json_response(self):
        text = """```json
{
  "rationale": "Sequential execution.",
  "steps": [
    {
      "step_number": 1,
      "action_type": "EndpointDiscovery",
      "parameters": {"target": "http://127.0.0.1:4280/"},
      "rationale": "Discover endpoints."
    },
    {
      "step_number": 2,
      "action_type": "ParameterDiscovery",
      "parameters": {"target": "http://127.0.0.1:4280/"},
      "rationale": "Discover parameters."
    },
    {
      "step_number": 3,
      "action_type": "ProofOfCompromise",
      "parameters": {"target": "http://127.0.0.1:4280/"},
      "rationale": "Verify impact."
    },
    {
      "step_number": 4,
      "action_type": "SQLInjectionProbe",
      "parameters": {"target": "http://127.0.0.1:4280/"},
```"""

        plan = self.adapter._parse_plan(text)

        self.assertIsNotNone(plan)
        self.assertEqual(len(plan.steps), 3)
        self.assertEqual(plan.steps[0].action_type, "EndpointDiscovery")
        self.assertEqual(plan.steps[2].action_type, "ProofOfCompromise")


class AIPlannerPlanProgressionTests(TestCase):
    def test_next_step_hint_skips_failed_exhausted_step(self):
        discovery = Phase.objects.create(name="discovery", description="Discovery")
        exploitation = Phase.objects.create(name="exploitation", description="Exploitation")

        endpoint = Command.objects.create(
            phase=discovery,
            name="EndpointDiscovery",
            description="Discover endpoints",
            command_template="dirsearch -u {target_url}",
        )
        proof = Command.objects.create(
            phase=exploitation,
            name="ProofOfCompromise",
            description="Verify compromise",
            command_template="echo proof",
        )

        state = AttackState.objects.create(
            name="Regression",
            current_phase="RECONNAISSANCE",
            state_data={
                "completed_commands": [endpoint.id],
            },
            current_plan={
                "steps": [
                    {"step_number": 1, "action_type": "EndpointDiscovery", "parameters": {}},
                    {"step_number": 2, "action_type": "ProofOfCompromise", "parameters": {}},
                ]
            },
        )
        ExecutionResult.objects.create(
            command=endpoint,
            attack_state=state,
            target="http://127.0.0.1:4280/",
            status="FAILED",
            stdout="",
            stderr="404",
            findings={},
        )

        planner = AIPlanner.__new__(AIPlanner)

        next_step = planner._next_step_hint(state)

        self.assertEqual(next_step["action_type"], proof.name)

    def test_ensure_initial_plan_scopes_to_current_phase(self):
        reconnaissance = Phase.objects.create(name="reconnaissance", description="Recon")
        discovery = Phase.objects.create(name="discovery", description="Discovery")

        header = Command.objects.create(
            phase=reconnaissance,
            name="HTTPHeaderFetch",
            description="Headers",
            command_template="curl -I {target_url}",
        )
        Command.objects.create(
            phase=discovery,
            name="EndpointDiscovery",
            description="Endpoints",
            command_template="python discover.py",
        )

        state = AttackState.objects.create(
            name="Phase only",
            current_phase="RECONNAISSANCE",
            state_data={"target": "http://127.0.0.1:4280/"},
        )

        from state.state_manager import StateManager

        planner = AIPlanner.__new__(AIPlanner)
        planner.last_plan_error = None
        planner.plan_adapter = PlanRecordingAdapter([header.name])
        planner._plan_task_key = AIPlanner._plan_task_key.__get__(planner, AIPlanner)
        planner._normalize_phase_key = AIPlanner._normalize_phase_key.__get__(planner, AIPlanner)
        planner._normalize_phase_name = AIPlanner._normalize_phase_name.__get__(planner, AIPlanner)
        planner._plan_phase = AIPlanner._plan_phase.__get__(planner, AIPlanner)
        planner._minimum_plan_steps = AIPlanner._minimum_plan_steps.__get__(planner, AIPlanner)
        planner._command_metadata = AIPlanner._command_metadata.__get__(planner, AIPlanner)
        planner._ensure_plan = AIPlanner._ensure_plan.__get__(planner, AIPlanner)

        ready = planner.ensure_initial_plan(StateManager(state.id))
        state.refresh_from_db()

        self.assertTrue(ready)
        self.assertEqual(state.current_plan["phase"], "reconnaissance")
        self.assertEqual(len(planner.plan_adapter.last_plan_input.available_commands), 1)
        self.assertEqual(planner.plan_adapter.last_plan_input.available_commands[0]["name"], header.name)
