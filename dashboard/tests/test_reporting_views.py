from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from core.models import AttackState, Command, ExecutionResult, Phase


class ReportingViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="report-user",
            email="report@example.com",
            password="secret123",
            is_active=True,
        )
        self.client.login(username="report-user", password="secret123")
        self.phase = Phase.objects.create(name="reconnaissance")
        self.command = Command.objects.create(
            phase=self.phase,
            name="HTTPHeaderFetch",
            description="fetch headers",
            command_template="curl -I {target}",
        )
        self.state = AttackState.objects.create(
            name="Reportable run",
            current_phase="RECONNAISSANCE",
            state_data={
                "findings": {"proof_summary": "demo evidence"},
                "level_history": [{"phase": "reconnaissance", "review": "done"}],
                "script_artifacts": [{"id": "script-1", "sha256": "abc", "language": "python"}],
            },
            current_plan={},
        )
        ExecutionResult.objects.create(
            command=self.command,
            attack_state=self.state,
            target="http://127.0.0.1",
            status="SUCCESS",
            stdout="ok",
            stderr="",
            findings={"headers": True},
        )

    def test_generate_report_persists_report_artifact(self):
        response = self.client.post(
            reverse("dashboard_attack_report_generate", kwargs={"pk": self.state.pk})
        )
        self.assertEqual(response.status_code, 302)
        self.state.refresh_from_db()
        reports = self.state.state_data.get("report_artifacts", [])
        self.assertTrue(reports)
        self.assertEqual(self.state.state_data.get("last_report_status"), "generated")

    def test_latest_report_endpoint_returns_latest_report_payload(self):
        self.client.post(reverse("dashboard_attack_report_generate", kwargs={"pk": self.state.pk}))
        response = self.client.get(
            reverse("dashboard_attack_report_latest", kwargs={"pk": self.state.pk})
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload.get("status"), "generated")
        self.assertIn("payload", payload)
