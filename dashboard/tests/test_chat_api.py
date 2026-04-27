import json
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from core.models import AttackState
from dashboard.chat_service import DashboardChatService


class DashboardChatApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="chat-user",
            email="chat@example.com",
            password="secret123",
            is_active=True,
        )
        self.client.login(username="chat-user", password="secret123")
        self.state = AttackState.objects.create(
            name="Chat Run",
            current_phase="reconnaissance",
            autonomy_status="STOPPED",
            stop_reason="Waiting for approval.",
            state_data={
                "target": "http://127.0.0.1:4280/",
                "findings": {"proof_summary": "demo evidence"},
                "level_history": [
                    {
                        "phase": "reconnaissance",
                        "review": "Recon found basic headers",
                        "details": {
                            "summary": "Recon summary",
                            "key_evidence": ["headers"],
                            "results_snapshot": [
                                {"command": "HTTPHeaderFetch", "status": "SUCCESS", "stdout_excerpt": "Server: Apache"}
                            ],
                        },
                    }
                ],
                "report_artifacts": [
                    {
                        "id": "report-1",
                        "generated_at": 1,
                        "status": "generated",
                        "payload": {"executive_summary": "Run summary"},
                    }
                ],
            },
            current_plan={
                "phase": "reconnaissance",
                "steps": [
                    {
                        "step_number": 1,
                        "action_type": "HTTPHeaderFetch",
                        "status": "failed",
                        "rationale": "Fetch headers",
                        "success_criteria": "Headers visible",
                        "execution_history": [
                            {"attempt_number": 1, "status": "FAILED", "stdout_excerpt": "connection refused"}
                        ],
                    }
                ],
            },
        )

    @patch.object(DashboardChatService, "_generate_answer", return_value="You should inspect the failed header fetch and verify target reachability.")
    def test_chat_api_returns_answer_and_updates_persisted_memory(self, mocked_generate):
        response = self.client.post(
            reverse("dashboard_attack_chat_ask"),
            data=json.dumps(
                {
                    "attack_id": self.state.id,
                    "message": "Why did this run fail?",
                    "include_recommendations": True,
                }
            ),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["success"])
        self.assertIn("inspect the failed header fetch", payload["answer"])
        self.assertTrue(payload["memory_summary_updated"])
        self.assertTrue(payload["evidence_refs"])

        self.state.refresh_from_db()
        self.assertIn("Why did this run fail?", self.state.state_data.get("chat_memory_summary", ""))
        self.assertTrue(self.state.state_data.get("chat_last_recommendations"))

    @patch.object(DashboardChatService, "_generate_answer", return_value="Phase explanation")
    def test_chat_api_supports_phase_specific_queries(self, mocked_generate):
        response = self.client.post(
            reverse("dashboard_attack_chat_ask"),
            data=json.dumps(
                {
                    "attack_id": self.state.id,
                    "message": "Explain this phase",
                    "phase_key": "reconnaissance",
                }
            ),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["phase"], "reconnaissance")
        self.assertTrue(any(ref.startswith("phase:") for ref in payload["evidence_refs"]))

    def test_chat_api_rejects_invalid_attack_id(self):
        response = self.client.post(
            reverse("dashboard_attack_chat_ask"),
            data=json.dumps({"attack_id": "abc", "message": "hello"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)

    @patch.object(DashboardChatService, "_generate_answer", return_value="reset ready")
    def test_chat_reset_clears_session_transcript(self, mocked_generate):
        ask_url = reverse("dashboard_attack_chat_ask")
        self.client.post(
            ask_url,
            data=json.dumps({"attack_id": self.state.id, "message": "Summarize the latest execution"}),
            content_type="application/json",
        )

        session = self.client.session
        self.assertTrue(session.get(DashboardChatService.SESSION_KEY, {}).get(str(self.state.id)))

        reset_response = self.client.post(
            reverse("dashboard_attack_chat_reset"),
            data=json.dumps({"attack_id": self.state.id}),
            content_type="application/json",
        )

        self.assertEqual(reset_response.status_code, 200)
        session = self.client.session
        self.assertFalse(session.get(DashboardChatService.SESSION_KEY, {}).get(str(self.state.id)))

    def test_dashboard_renders_ai_assistant_panel(self):
        response = self.client.get(reverse("dashboard_index"), {"attack_id": self.state.id})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "AI Assistant")
        self.assertContains(response, "Open Assistant")

    def test_assistant_page_renders_with_selected_run(self):
        response = self.client.get(reverse("dashboard_assistant"), {"attack_id": self.state.id})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Explain runs, failures, phases, and next steps.")
        self.assertContains(response, self.state.name)
