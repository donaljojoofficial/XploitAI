from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from core.models import AttackContext, AttackerExecutor, AttackState, AttackTarget


class ExecutorManagementTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="ops",
            email="ops@example.com",
            password="secret123",
            is_active=True,
        )
        self.client.login(username="ops", password="secret123")

    def test_can_create_ssh_executor_from_management_page(self):
        response = self.client.post(
            reverse("executor_management"),
            data={
                "save_executor": "1",
                "name": "Kali SSH",
                "executor_type": AttackerExecutor.ExecutorType.SSH,
                "ip_address": "192.168.56.20",
                "ssh_port": "22",
                "ssh_username": "kali",
                "ssh_auth_type": AttackerExecutor.SSHAuthType.PASSWORD,
                "ssh_password": "supersecret",
                "ssh_private_key_path": "",
                "ssh_working_directory": "/home/kali",
            },
        )

        self.assertEqual(response.status_code, 302)
        executor = AttackerExecutor.objects.get(name="Kali SSH")
        self.assertEqual(executor.executor_type, AttackerExecutor.ExecutorType.SSH)
        self.assertEqual(executor.ssh_username, "kali")
        self.assertTrue(executor.is_remote_ready)

    def test_ssh_executor_requires_auth_material(self):
        response = self.client.post(
            reverse("executor_management"),
            data={
                "save_executor": "1",
                "name": "Broken SSH",
                "executor_type": AttackerExecutor.ExecutorType.SSH,
                "ip_address": "192.168.56.21",
                "ssh_port": "22",
                "ssh_username": "kali",
                "ssh_auth_type": AttackerExecutor.SSHAuthType.PRIVATE_KEY,
                "ssh_password": "",
                "ssh_private_key_path": "",
                "ssh_working_directory": "",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Private key path is required")
        self.assertFalse(AttackerExecutor.objects.filter(name="Broken SSH").exists())


class SSHStartAttackTests(TestCase):
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
        self.executor = AttackerExecutor.objects.create(
            name="SSH Runner",
            executor_type=AttackerExecutor.ExecutorType.SSH,
            ip_address="192.168.56.30",
            ssh_port=22,
            ssh_username="kali",
            ssh_auth_type=AttackerExecutor.SSHAuthType.PASSWORD,
            ssh_password="topsecret",
        )

    @patch("dashboard.views._launch_assessment")
    @patch("dashboard.views._verify_executor_is_live", return_value=(True, "SSH connection established."))
    def test_start_attack_uses_ssh_execution_mode_for_ssh_executor(self, verify_executor, launch_assessment):
        response = self.client.post(
            reverse("dashboard_start_attack"),
            data={
                "target_id": str(self.target.id),
                "executor_id": str(self.executor.id),
                "llm_provider": "auto",
            },
        )

        self.assertEqual(response.status_code, 302)
        state = AttackState.objects.order_by("-created_at").first()
        self.assertEqual(state.state_data.get("execution_mode"), "ssh")
        self.assertEqual(state.state_data.get("executor_id"), self.executor.id)
        self.assertTrue(AttackContext.objects.filter(attacker_executor=self.executor, target=self.target).exists())
        verify_executor.assert_called_once_with(self.executor)
        launch_assessment.assert_called_once()

    @patch("dashboard.views._launch_assessment")
    @patch("dashboard.views._verify_executor_is_live", return_value=(False, "SSH executor 'SSH Runner' is not reachable: timed out"))
    def test_start_attack_blocks_unreachable_ssh_executor(self, verify_executor, launch_assessment):
        response = self.client.post(
            reverse("dashboard_start_attack"),
            data={
                "target_id": str(self.target.id),
                "executor_id": str(self.executor.id),
                "llm_provider": "auto",
            },
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "SSH executor &#x27;SSH Runner&#x27; is not reachable: timed out")
        self.assertEqual(AttackState.objects.count(), 0)
        verify_executor.assert_called_once_with(self.executor)
        launch_assessment.assert_not_called()
