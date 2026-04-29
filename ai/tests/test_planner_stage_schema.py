from django.test import TestCase

from ai.planner import AIPlanner
from ai.schemas import DecisionInput, Plan, PlanStep
from core.models import AttackState


class PlannerStageSchemaTests(TestCase):
    def test_serialize_step_adds_stage_and_script_schema(self):
        planner = AIPlanner(provider="local")
        state = AttackState.objects.create(
            name="planner-schema",
            current_phase="EXPLOITATION",
            state_data={"runtime_profile": {"max_retries": 2, "retry_cooldown_seconds": 2}},
        )
        step = PlanStep(
            step_number=1,
            action_type="PayloadGeneration",
            parameters={"target": "http://127.0.0.1"},
            rationale="Generate payload after exploit path is available.",
        )

        serialized = planner._serialize_plan_step(state, step, state.state_data.get("runtime_profile"), "exploitation")

        self.assertEqual(serialized["stage_label"], "exploitation")
        self.assertEqual(serialized["execution_type"], "script")
        self.assertEqual(serialized["script_language"], "python")
        self.assertTrue(serialized["script_content"])
        self.assertIn("success_criteria", serialized)

    def test_supplement_plan_keeps_payload_paths_reachable(self):
        planner = AIPlanner(provider="local")
        decision_input = DecisionInput(
            phase="exploitation",
            known_services=[],
            past_actions=[],
            available_commands=[
                {"id": 1, "name": "ExploitAttempt"},
                {"id": 2, "name": "PayloadGeneration"},
                {"id": 3, "name": "ExploitScriptGeneration"},
            ],
        )

        supplemented = planner._supplement_plan_with_available_commands(
            plan=None,
            decision_input=decision_input,
            available_command_metadata=decision_input.available_commands or [],
        )

        self.assertIsNotNone(supplemented)
        names = [step.action_type for step in supplemented.steps]
        self.assertIn("PayloadGeneration", names)
        self.assertIn("ExploitScriptGeneration", names)

    def test_next_step_hint_preserves_resolved_command_metadata(self):
        planner = AIPlanner(provider="local")
        state = AttackState.objects.create(
            name="planner-hint",
            current_phase="EXPLOITATION",
            current_plan={
                "phase": "exploitation",
                "steps": [
                    {
                        "step_number": 1,
                        "action_type": "ExploitAttempt",
                        "parameters": {"target": "http://127.0.0.1"},
                        "resolved_command": "python -c \"print('locked')\"",
                        "resolved_tools": ["python"],
                        "execution_type": "script",
                        "script_language": "python",
                        "script_content": "print('locked')",
                        "artifact_refs": [{"id": "script-1"}],
                        "success_criteria": "Exploit evidence observed.",
                        "status": "pending",
                    }
                ],
            },
        )

        hint = planner._next_step_hint(state)
        self.assertIsNotNone(hint)
        self.assertEqual(hint.get("resolved_command"), "python -c \"print('locked')\"")
        self.assertEqual(hint.get("execution_type"), "script")
        self.assertEqual(hint.get("script_language"), "python")

    def test_dedupe_plan_steps_removes_repeated_actions(self):
        planner = AIPlanner(provider="local")
        plan = Plan(
            rationale="duplicate plan",
            steps=[
                PlanStep(step_number=1, action_type="EndpointDiscovery", parameters={}, rationale="first"),
                PlanStep(step_number=2, action_type="EndpointDiscovery", parameters={}, rationale="repeat"),
                PlanStep(step_number=3, action_type="ParameterDiscovery", parameters={}, rationale="next"),
            ],
        )

        deduped = planner._dedupe_plan_steps(plan)

        self.assertEqual([step.action_type for step in deduped.steps], ["EndpointDiscovery", "ParameterDiscovery"])
        self.assertEqual([step.step_number for step in deduped.steps], [1, 2])
