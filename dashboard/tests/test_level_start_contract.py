from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from core.models import AttackTarget, AttackState, Command, Phase
from dashboard.views import _launch_assessment
from services.tool_preflight import TOOL_PREFLIGHT_STATE_KEY, RECOMMENDED_TOOL_INSTALL_COMMAND


class LevelStartContractTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="starter",
            email="starter@example.com",
            password="secret123",
            is_active=True,
        )
        self.client.login(username="starter", password="secret123")
        self.target = AttackTarget.objects.create(
            name="DVWA",
            base_url="http://127.0.0.1:4280/",
            operating_system="Linux",
            is_active=True,
        )

    @patch("dashboard.views._launch_assessment")
    def test_start_attack_persists_level_runtime_defaults(self, launch_assessment):
        response = self.client.post(
            reverse("dashboard_start_attack"),
            data={
                "target_id": str(self.target.id),
                "llm_provider": "auto",
                "progression_mode": "manual",
                "max_retries": "2",
                "retry_cooldown_seconds": "2",
                "max_step_attempts_per_level": "5",
                "max_level_failures": "3",
                "max_level_runtime_seconds": "300",
            },
        )

        self.assertEqual(response.status_code, 302)
        state = AttackState.objects.order_by("-created_at").first()
        self.assertIsNotNone(state)
        self.assertEqual(state.state_data.get("progression_mode"), "manual")
        self.assertTrue(state.state_data.get("plan_command_lock"))
        self.assertEqual(state.state_data.get("runtime_profile", {}).get("max_retries"), 2)
        self.assertEqual(state.state_data.get("runtime_profile", {}).get("retry_cooldown_seconds"), 2)
        self.assertEqual(
            state.state_data.get("runtime_profile", {}).get("limits", {}).get("max_step_attempts_per_level"),
            5,
        )
        launch_assessment.assert_called_once()

    @patch("dashboard.views._launch_assessment")
    def test_start_attack_accepts_selected_start_phase(self, launch_assessment):
        response = self.client.post(
            reverse("dashboard_start_attack"),
            data={
                "target_id": str(self.target.id),
                "llm_provider": "auto",
                "start_phase": "discovery",
            },
        )

        self.assertEqual(response.status_code, 302)
        state = AttackState.objects.order_by("-created_at").first()
        self.assertEqual(state.current_phase, "discovery")
        self.assertEqual(state.state_data.get("current_phase"), "discovery")
        self.assertEqual(state.state_data.get("start_phase"), "discovery")
        launch_assessment.assert_called_once()

    @patch("dashboard.views._launch_assessment")
    def test_start_attack_can_request_recommended_tool_preflight(self, launch_assessment):
        response = self.client.post(
            reverse("dashboard_start_attack"),
            data={
                "target_id": str(self.target.id),
                "llm_provider": "auto",
                "install_recommended_tools": "1",
            },
        )

        self.assertEqual(response.status_code, 302)
        state = AttackState.objects.order_by("-created_at").first()
        preflight = state.state_data.get(TOOL_PREFLIGHT_STATE_KEY)
        self.assertIsInstance(preflight, dict)
        self.assertTrue(preflight.get("enabled"))
        self.assertEqual(preflight.get("status"), "pending")
        self.assertEqual(preflight.get("command"), RECOMMENDED_TOOL_INSTALL_COMMAND)
        launch_assessment.assert_called_once()

    @patch("dashboard.views.ExecutionService")
    def test_launch_assessment_uses_runtime_profile_level_limit_for_local_runtime_cap(self, execution_service_cls):
        state = AttackState.objects.create(
            name="Runtime limit",
            current_phase="reconnaissance",
            autonomy_status="IDLE",
            state_data={
                "execution_mode": "local",
                "llm_provider": "auto",
                "runtime_profile": {
                    "max_retries": 2,
                    "retry_cooldown_seconds": 2,
                    "limits": {
                        "max_step_attempts_per_level": 5,
                        "max_level_failures": 3,
                        "max_level_runtime_seconds": 300,
                    },
                },
            },
            current_plan={},
        )

        _launch_assessment(state)

        execution_service_cls.assert_called_once()
        self.assertEqual(execution_service_cls.call_args.kwargs["max_time_seconds"], 300)

    @patch("dashboard.views._launch_assessment")
    def test_start_attack_reuses_selected_test_and_preserves_findings(self, launch_assessment):
        discovery = Phase.objects.create(name="discovery", description="Discovery")
        enumeration_cmd = Command.objects.create(
            phase=discovery,
            name="EndpointDiscovery",
            description="Enumerate",
            command_template="dirsearch -u {target_url}",
        )
        state = AttackState.objects.create(
            name="Existing Test",
            current_phase="discovery",
            autonomy_status="STOPPED",
            state_data={
                "target": "http://127.0.0.1:4280/",
                "findings": {"identified_technologies": ["WordPress"]},
                "level_history": [{"phase": "reconnaissance", "findings": {"server_banner": "Apache"}}],
                "completed_commands": [enumeration_cmd.id],
            },
            current_plan={"phase": "discovery", "steps": [{"action_type": "EndpointDiscovery", "command_id": enumeration_cmd.id, "status": "failed"}]},
        )

        response = self.client.post(
            reverse("dashboard_start_attack"),
            data={
                "continue_attack_id": str(state.id),
                "target_id": str(self.target.id),
                "llm_provider": "auto",
                "start_phase": "discovery",
            },
        )

        state.refresh_from_db()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(AttackState.objects.count(), 1)
        self.assertEqual(state.state_data.get("findings", {}).get("identified_technologies"), ["WordPress"])
        self.assertEqual(state.state_data.get("level_history", [])[0]["phase"], "reconnaissance")
        self.assertEqual(state.state_data.get("level_history", [])[1]["phase"], "discovery")
        self.assertEqual(
            state.state_data.get("level_history", [])[1]["details"]["plan_snapshot"][0]["action_type"],
            "EndpointDiscovery",
        )
        self.assertEqual(state.current_plan, {})
        self.assertEqual(state.state_data.get("completed_commands"), [])
        launch_assessment.assert_called_once()

    @patch("dashboard.views._launch_assessment")
    def test_start_attack_allows_overriding_completed_requested_phase(self, launch_assessment):
        state = AttackState.objects.create(
            name="Completed Recon Test",
            current_phase="discovery",
            autonomy_status="STOPPED",
            state_data={
                "target": "http://127.0.0.1:4280/",
                "level_history": [{"phase": "reconnaissance", "findings": {"server_banner": "Apache"}}],
                "findings": {"server_banner": "Apache"},
            },
            current_plan={},
        )

        response = self.client.post(
            reverse("dashboard_start_attack"),
            data={
                "continue_attack_id": str(state.id),
                "target_id": str(self.target.id),
                "llm_provider": "auto",
                "start_phase": "reconnaissance",
            },
        )

        state.refresh_from_db()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(state.current_phase, "reconnaissance")
        self.assertEqual(state.state_data.get("start_phase"), "reconnaissance")
        self.assertEqual(state.state_data.get("requested_start_phase"), "reconnaissance")
        self.assertFalse(state.state_data.get("plan_approved"))
        launch_assessment.assert_called_once()

    @patch("dashboard.views._launch_assessment")
    def test_start_attack_treats_completed_current_plan_as_completed_phase(self, launch_assessment):
        state = AttackState.objects.create(
            name="Completed Discovery Test",
            current_phase="discovery",
            autonomy_status="STOPPED",
            state_data={
                "target": "http://127.0.0.1:4280/",
                "level_history": [{"phase": "reconnaissance", "findings": {"server_banner": "Apache"}}],
                "findings": {"identified_technologies": ["DVWA"]},
            },
            current_plan={
                "phase": "discovery",
                "steps": [
                    {
                        "step_number": 1,
                        "action_type": "EndpointDiscovery",
                        "status": "completed",
                        "execution_history": [{"status": "SUCCESS", "stdout_excerpt": "ok"}],
                    }
                ],
            },
        )

        response = self.client.post(
            reverse("dashboard_start_attack"),
            data={
                "continue_attack_id": str(state.id),
                "target_id": str(self.target.id),
                "llm_provider": "auto",
                "start_phase": "discovery",
            },
        )

        state.refresh_from_db()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(state.current_phase, "discovery")
        self.assertEqual(state.state_data.get("start_phase"), "discovery")
        self.assertEqual(state.state_data.get("level_history", [])[1]["phase"], "discovery")
        self.assertFalse(state.state_data.get("plan_approved"))
        launch_assessment.assert_called_once()
