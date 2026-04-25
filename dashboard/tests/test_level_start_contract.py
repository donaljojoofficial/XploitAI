from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from core.models import AttackTarget, AttackState


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
        self.assertEqual(state.state_data.get("runtime_profile", {}).get("max_retries"), 2)
        self.assertEqual(state.state_data.get("runtime_profile", {}).get("retry_cooldown_seconds"), 2)
        self.assertEqual(
            state.state_data.get("runtime_profile", {}).get("limits", {}).get("max_step_attempts_per_level"),
            5,
        )
        launch_assessment.assert_called_once()

