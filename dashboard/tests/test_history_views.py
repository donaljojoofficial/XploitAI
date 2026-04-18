from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from core.models import AttackState
from dashboard.views import _build_attack_run_history


class AttackHistoryViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="history-user",
            email="history@example.com",
            password="secret123",
            is_active=True,
        )
        self.client.login(username="history-user", password="secret123")

    def test_build_attack_run_history_includes_reviewed_and_active_phases(self):
        state = AttackState.objects.create(
            name="Historical operation",
            current_phase="ENUMERATION",
            autonomy_status="STOPPED",
            state_data={
                "findings": {"live_host": "10.0.0.5"},
                "phase_reviews": [
                    {
                        "phase": "reconnaissance",
                        "review": "Recon complete",
                        "next_phase": "enumeration",
                        "details": {
                            "summary": "Recon summary",
                            "plan_snapshot": [
                                {
                                    "step_number": 1,
                                    "action_type": "PassiveRecon",
                                    "rationale": "Identify target",
                                }
                            ],
                            "results_snapshot": [
                                {
                                    "command": "PassiveRecon",
                                    "status": "SUCCESS",
                                    "stdout_excerpt": "Resolved host",
                                    "findings": {"resolved_ips_target": ["10.0.0.5"]},
                                }
                            ],
                            "current_findings": {"resolved_ips_target": ["10.0.0.5"]},
                        },
                    }
                ],
            },
            current_plan={
                "phase": "enumeration",
                "rationale": "Enumerate services",
                "steps": [
                    {
                        "step_number": 1,
                        "action_type": "ServiceEnumeration",
                        "parameters": {"target_host": "10.0.0.5"},
                        "rationale": "Enumerate open ports",
                    }
                ],
            },
        )

        history = _build_attack_run_history(state)

        self.assertEqual(history["summary"]["phases"], 2)
        self.assertEqual(history["summary"]["total"], 2)
        self.assertEqual(history["phases"][0]["phase"], "reconnaissance")
        self.assertEqual(history["phases"][0]["steps"][0]["status"], "completed")
        self.assertEqual(history["phases"][1]["phase"], "enumeration")
        self.assertEqual(history["phases"][1]["steps"][0]["action_type"], "ServiceEnumeration")

    def test_test_history_page_lists_all_initiated_tests(self):
        AttackState.objects.create(
            name="Run One",
            current_phase="RECONNAISSANCE",
            autonomy_status="STOPPED",
            state_data={"phase_reviews": []},
            current_plan={},
        )
        AttackState.objects.create(
            name="Run Two",
            current_phase="ENUMERATION",
            autonomy_status="RUNNING",
            state_data={
                "findings": {"banner": "Apache"},
                "phase_reviews": [
                    {
                        "phase": "reconnaissance",
                        "review": "Recon complete",
                        "details": {
                            "plan_snapshot": [{"step_number": 1, "action_type": "PassiveRecon"}],
                            "results_snapshot": [{"command": "PassiveRecon", "status": "SUCCESS"}],
                        },
                    }
                ],
            },
            current_plan={
                "phase": "enumeration",
                "steps": [{"step_number": 1, "action_type": "ServiceEnumeration"}],
            },
        )

        response = self.client.get(reverse("dashboard_test_history"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "All Initiated Test Runs")
        self.assertContains(response, "Run One")
        self.assertContains(response, "Run Two")
        self.assertContains(response, "Recon complete")
