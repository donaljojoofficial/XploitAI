from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from core.models import AttackState
from dashboard.views import _build_attack_run_history, _build_phase_cards


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
        self.assertContains(response, "Delete All Tests")
        self.assertContains(response, "Delete")

    def test_delete_single_test_history_item(self):
        state = AttackState.objects.create(
            name="Delete Me",
            current_phase="reconnaissance",
            autonomy_status="STOPPED",
            state_data={},
            current_plan={},
        )
        keep = AttackState.objects.create(
            name="Keep Me",
            current_phase="discovery",
            autonomy_status="STOPPED",
            state_data={},
            current_plan={},
        )

        response = self.client.post(reverse("dashboard_attack_delete", kwargs={"pk": state.pk}))

        self.assertEqual(response.status_code, 302)
        self.assertFalse(AttackState.objects.filter(pk=state.pk).exists())
        self.assertTrue(AttackState.objects.filter(pk=keep.pk).exists())

    def test_delete_all_test_history_items(self):
        AttackState.objects.create(
            name="Run One",
            current_phase="reconnaissance",
            autonomy_status="STOPPED",
            state_data={},
            current_plan={},
        )
        AttackState.objects.create(
            name="Run Two",
            current_phase="discovery",
            autonomy_status="STOPPED",
            state_data={},
            current_plan={},
        )

        response = self.client.post(reverse("dashboard_test_history_delete_all"))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(AttackState.objects.count(), 0)

    def test_phase_cards_mark_skipped_earlier_phases_for_later_start(self):
        state = AttackState.objects.create(
            name="Later start run",
            current_phase="discovery",
            autonomy_status="RUNNING",
            state_data={"start_phase": "discovery"},
            current_plan={
                "phase": "discovery",
                "steps": [{"step_number": 1, "action_type": "EndpointDiscovery"}],
            },
        )

        phase_dashboard = _build_phase_cards(state)
        cards = {card["phase_key"]: card for card in phase_dashboard["cards"]}

        self.assertTrue(cards["reconnaissance"]["is_skipped_by_start"])
        self.assertEqual(cards["reconnaissance"]["status"], "pending")
        self.assertEqual(cards["discovery"]["status"], "running")

    def test_dashboard_index_supports_attack_selection_and_phase_page(self):
        older = AttackState.objects.create(
            name="Older Run",
            current_phase="reconnaissance",
            autonomy_status="STOPPED",
            state_data={"phase_reviews": []},
            current_plan={},
        )
        newer = AttackState.objects.create(
            name="Selected Run",
            current_phase="discovery",
            autonomy_status="RUNNING",
            state_data={"start_phase": "discovery"},
            current_plan={
                "phase": "discovery",
                "steps": [{"step_number": 1, "action_type": "EndpointDiscovery"}],
            },
        )

        response = self.client.get(reverse("dashboard_index"), {"attack_id": newer.id})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Pentest Phase Map")
        self.assertContains(response, "Run Phase Status")
        self.assertContains(response, "Selected Run")
        self.assertNotContains(response, "No selected run")

        phase_response = self.client.get(
            reverse("dashboard_attack_phase_detail", kwargs={"pk": newer.pk, "phase_key": "discovery"}),
            {"tab": "overview"},
        )
        self.assertEqual(phase_response.status_code, 200)
        self.assertContains(phase_response, "Enumeration")
        self.assertContains(phase_response, "Current Phase")

    def test_dashboard_index_includes_create_new_test_option(self):
        AttackState.objects.create(
            name="Existing Run",
            current_phase="reconnaissance",
            autonomy_status="IDLE",
            state_data={},
            current_plan={},
        )

        response = self.client.get(reverse("dashboard_index"), {"attack_id": "__new__"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Create New Test...")
        self.assertContains(response, 'startModalOpen: true', html=False)

    def test_phase_detail_empty_state_for_unstarted_phase(self):
        state = AttackState.objects.create(
            name="Phase empty",
            current_phase="discovery",
            autonomy_status="RUNNING",
            state_data={"start_phase": "discovery"},
            current_plan={"phase": "discovery", "steps": []},
        )

        response = self.client.get(
            reverse("dashboard_attack_phase_detail", kwargs={"pk": state.pk, "phase_key": "exploitation"})
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "has not been executed in this run")

    def test_phase_detail_invalid_phase_returns_404(self):
        state = AttackState.objects.create(
            name="Invalid phase",
            current_phase="reconnaissance",
            autonomy_status="IDLE",
            state_data={},
            current_plan={},
        )

        response = self.client.get(
            reverse("dashboard_attack_phase_detail", kwargs={"pk": state.pk, "phase_key": "nonsense"})
        )

        self.assertEqual(response.status_code, 404)
