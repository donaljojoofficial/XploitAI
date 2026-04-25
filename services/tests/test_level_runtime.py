from django.test import TestCase

from core.models import AttackState
from services.execution_service import ExecutionService


class LevelRuntimeTests(TestCase):
    def _make_state(self) -> AttackState:
        return AttackState.objects.create(
            name="Runtime",
            current_phase="RECONNAISSANCE",
            current_plan={
                "phase": "reconnaissance",
                "level": {"index": 1, "phase_name": "reconnaissance", "kill_chain_label": "RECONNAISSANCE"},
                "limits": {
                    "max_step_attempts_per_level": 5,
                    "max_level_failures": 3,
                    "max_level_runtime_seconds": 300,
                },
                "runtime": {"level_started_at": 0, "total_attempts": 0, "total_failures": 0},
                "steps": [
                    {
                        "step_number": 1,
                        "action_type": "HTTPHeaderFetch",
                        "status": "pending",
                        "attempt_count": 0,
                        "command_retry_count": 0,
                        "max_retries": 2,
                        "retry_cooldown_seconds": 2,
                        "execution_history": [],
                    }
                ],
            },
        )

    def test_update_step_state_schedules_retry_with_cooldown(self):
        state = self._make_state()
        service = ExecutionService(attack_state_id=state.id, llm_provider="local")

        service._update_step_execution_state(
            "HTTPHeaderFetch",
            status="FAILED",
            command="curl -I http://127.0.0.1",
            command_retries=1,
            stderr="timeout",
            schedule_retry=True,
            next_allowed_at=123.0,
        )
        state.refresh_from_db()
        step = state.current_plan["steps"][0]
        self.assertEqual(step["status"], "pending")
        self.assertTrue(step["cooldown_pending"])
        self.assertEqual(step["command_retry_count"], 1)
        self.assertEqual(step["execution_history"][0]["status"], "RETRY_SCHEDULED")

    def test_level_limit_reason_triggers_when_attempt_cap_hit(self):
        state = self._make_state()
        service = ExecutionService(attack_state_id=state.id, llm_provider="local")

        for _ in range(5):
            service._record_level_runtime(success=False)

        state.refresh_from_db()
        reason = service._level_limit_reason(state)
        self.assertIn("Level rate limit reached", reason)

