from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from core.models import AttackState
from dashboard.views import _build_attack_run_history, _build_plan_view_state


class PhaseApprovalFlowTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="phase-user",
            email="phase@example.com",
            password="secret123",
            is_active=True,
        )
        self.client.login(username="phase-user", password="secret123")

    def test_plan_view_keeps_phase_review_state_when_current_plan_is_empty(self):
        state = AttackState.objects.create(
            name="Inter-phase state",
            current_phase="RECONNAISSANCE",
            state_data={
                "phase_reviews": [{"phase": "reconnaissance", "review": "done"}],
                "level_history": [{"phase": "reconnaissance", "review": "done"}],
                "phase_transition_pending": {
                    "from_phase": "reconnaissance",
                    "next_phase": "discovery",
                    "review": "move on",
                },
                "level_transition_pending": {
                    "from_phase": "reconnaissance",
                    "next_phase": "discovery",
                    "review": "move on",
                },
            },
            current_plan={},
        )

        view_state = _build_plan_view_state(state)

        self.assertEqual(view_state["steps"], [])
        self.assertEqual(len(view_state["phase_reviews"]), 1)
        self.assertEqual(len(view_state["level_history"]), 1)
        self.assertEqual(
            view_state["phase_transition_pending"]["next_phase"],
            "discovery",
        )
        self.assertEqual(
            view_state["level_transition_pending"]["next_phase"],
            "discovery",
        )

    @patch("dashboard.views._launch_assessment")
    def test_approve_plan_marks_displayed_plan_approved_even_after_phase_review(self, launch_assessment):
        state = AttackState.objects.create(
            name="Phase two plan ready",
            current_phase="discovery",
            autonomy_status="STOPPED",
            stop_reason="Phase 'reconnaissance' reviewed. Plan for 'discovery' generated and waiting for approval.",
            state_data={
                "phase_reviews": [
                    {
                        "phase": "reconnaissance",
                        "review": "good to advance",
                        "next_phase": "discovery",
                    }
                ],
                "plan_approved": False,
            },
            current_plan={
                "phase": "discovery",
                "steps": [{"step_number": 1, "action_type": "EndpointDiscovery"}],
            },
        )

        response = self.client.post(reverse("approve_plan", kwargs={"pk": state.pk}))
        state.refresh_from_db()

        self.assertEqual(response.status_code, 302)
        self.assertEqual(state.current_phase, "discovery")
        self.assertTrue(state.state_data["plan_approved"])
        self.assertNotIn("phase_transition_pending", state.state_data)
        self.assertNotIn("level_transition_pending", state.state_data)
        launch_assessment.assert_called_once()

    @patch("dashboard.views._launch_assessment")
    def test_approve_plan_without_transition_marks_current_plan_approved(self, launch_assessment):
        state = AttackState.objects.create(
            name="Direct plan approval",
            current_phase="RECONNAISSANCE",
            autonomy_status="STOPPED",
            stop_reason="Plan generated. Waiting for approval.",
            state_data={
                "plan_approved": False,
                "auto_approve_generated_plan": True,
            },
            current_plan={
                "phase": "reconnaissance",
                "steps": [{"step_number": 1, "action_type": "HTTPHeaderFetch"}],
            },
        )

        response = self.client.post(reverse("approve_plan", kwargs={"pk": state.pk}))
        state.refresh_from_db()

        self.assertEqual(response.status_code, 302)
        self.assertTrue(state.state_data["plan_approved"])
        self.assertNotIn("auto_approve_generated_plan", state.state_data)
        launch_assessment.assert_called_once()

    def test_plan_view_uses_explicit_step_execution_state_for_ordering(self):
        state = AttackState.objects.create(
            name="Ordered phase plan",
            current_phase="RECONNAISSANCE",
            autonomy_status="STOPPED",
            state_data={
                "script_artifacts": [{"id": "script-1", "sha256": "abc", "language": "python"}],
            },
            current_plan={
                "phase": "reconnaissance",
                "steps": [
                    {
                        "step_number": 1,
                        "action_type": "HTTPHeaderFetch",
                        "status": "completed",
                        "attempt_count": 1,
                        "execution_history": [{"attempt_number": 1, "status": "SUCCESS"}],
                    },
                    {
                        "step_number": 2,
                        "action_type": "EndpointDiscovery",
                        "execution_type": "script",
                        "script_language": "python",
                        "script_content": "print('test')",
                        "artifact_refs": [{"id": "script-1"}],
                        "status": "failed",
                        "attempt_count": 2,
                        "command_retry_count": 1,
                        "alternative_pending": True,
                        "last_error_excerpt": "timed out",
                        "execution_history": [
                            {"attempt_number": 1, "status": "FAILED", "stderr_excerpt": "timed out"}
                        ],
                    },
                ],
            },
        )

        view_state = _build_plan_view_state(state)

        self.assertEqual(view_state["steps"][0]["status"], "completed")
        self.assertEqual(view_state["steps"][1]["status"], "failed")
        self.assertEqual(view_state["steps"][1]["attempt_count"], 2)
        self.assertTrue(view_state["steps"][1]["alternative_pending"])
        self.assertEqual(view_state["summary"]["attempts"], 3)
        self.assertEqual(view_state["steps"][1]["execution_type"], "script")
        self.assertTrue(view_state["steps"][1]["linked_script_artifacts"])
        self.assertEqual(view_state["stage_label"], "planning_recon")

    def test_attack_run_history_uses_active_phase_execution_history_not_global_results(self):
        state = AttackState.objects.create(
            name="History uses phase attempts",
            current_phase="RECONNAISSANCE",
            current_plan={
                "phase": "reconnaissance",
                "steps": [
                    {
                        "step_number": 1,
                        "action_type": "HTTPHeaderFetch",
                        "status": "failed",
                        "attempt_count": 1,
                        "alternative_pending": True,
                        "execution_history": [
                            {
                                "attempt_number": 1,
                                "command": "curl -I http://example.test",
                                "status": "FAILED",
                                "stderr_excerpt": "connection refused",
                            }
                        ],
                    }
                ],
            },
        )

        history = _build_attack_run_history(state)

        self.assertEqual(len(history["phases"]), 1)
        self.assertEqual(history["phases"][0]["outputs"][0]["command"], "curl -I http://example.test")
        self.assertEqual(history["phases"][0]["outputs"][0]["status"], "FAILED")

    def test_plan_view_prefers_step_execution_history_over_global_command_result(self):
        state = AttackState.objects.create(
            name="Plan view command sync",
            current_phase="RECONNAISSANCE",
            autonomy_status="STOPPED",
            current_plan={
                "phase": "reconnaissance",
                "steps": [
                    {
                        "step_number": 1,
                        "action_type": "HTTPHeaderFetch",
                        "attempt_count": 1,
                        "execution_history": [
                            {
                                "attempt_number": 1,
                                "command": "curl -I http://127.0.0.1:4280/",
                                "status": "FAILED",
                                "stderr_excerpt": "connection refused",
                            }
                        ],
                    }
                ],
            },
        )

        view_state = _build_plan_view_state(state)

        self.assertEqual(view_state["steps"][0]["command_preview"], "curl -I http://127.0.0.1:4280/")
        self.assertEqual(view_state["steps"][0]["command_preview_source"], "executor")
        self.assertEqual(view_state["steps"][0]["output_excerpt"], "connection refused")
        self.assertEqual(view_state["steps"][0]["status"], "failed")

    def test_plan_view_uses_rule_based_tool_preview_for_discovery_steps(self):
        state = AttackState.objects.create(
            name="Plan tool preview",
            current_phase="DISCOVERY",
            autonomy_status="STOPPED",
            state_data={"target": "http://127.0.0.1:4280/"},
            current_plan={
                "phase": "discovery",
                "steps": [
                    {
                        "step_number": 1,
                        "action_type": "EndpointDiscovery",
                        "parameters": {"target_url": "http://127.0.0.1:4280/"},
                    }
                ],
            },
        )

        view_state = _build_plan_view_state(state)

        self.assertIn("dirsearch", view_state["steps"][0]["command_preview"])
        self.assertEqual(view_state["steps"][0]["command_preview_source"], "rule_based")

    @patch("dashboard.views._launch_assessment")
    def test_retry_failed_phase_resets_unresolved_steps_and_relaunches(self, launch_assessment):
        state = AttackState.objects.create(
            name="Retryable phase",
            current_phase="DISCOVERY",
            autonomy_status="STOPPED",
            stop_reason="Phase failed.",
            state_data={"completed_commands": [11, 12, 13]},
            current_plan={
                "phase": "discovery",
                "steps": [
                    {
                        "step_number": 1,
                        "action_type": "HTTPHeaderFetch",
                        "command_id": 11,
                        "status": "completed",
                    },
                    {
                        "step_number": 2,
                        "action_type": "EndpointDiscovery",
                        "command_id": 12,
                        "status": "failed",
                        "command_retry_count": 2,
                        "next_allowed_at": 9999999999,
                        "alternative_pending": True,
                    },
                    {
                        "step_number": 3,
                        "action_type": "ParameterDiscovery",
                        "command_id": 13,
                        "status": "pending",
                        "command_retry_count": 1,
                    },
                ],
            },
        )

        response = self.client.post(reverse("retry_failed_phase", kwargs={"pk": state.pk}))
        state.refresh_from_db()

        self.assertEqual(response.status_code, 302)
        self.assertEqual(state.current_plan["steps"][1]["status"], "pending")
        self.assertEqual(state.current_plan["steps"][1]["command_retry_count"], 0)
        self.assertEqual(state.current_plan["steps"][1]["next_allowed_at"], 0)
        self.assertFalse(state.current_plan["steps"][1]["alternative_pending"])
        self.assertEqual(state.state_data["completed_commands"], [11])
        self.assertTrue(state.state_data["plan_approved"])
        self.assertIn("dirsearch", state.current_plan["steps"][1]["resolved_command"])
        launch_assessment.assert_called_once()
