from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from core.models import AttackState
from dashboard.views import _build_plan_view_state


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
                "phase_transition_pending": {
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
        self.assertEqual(
            view_state["phase_transition_pending"]["next_phase"],
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
