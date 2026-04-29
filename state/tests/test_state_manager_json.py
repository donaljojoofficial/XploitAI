import json
import tempfile
from pathlib import Path

from django.test import TestCase, override_settings

from core.models import AttackState
from state.state_manager import StateManager


class JsonStateManagerTests(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

    def test_record_phase_output_persists_scanning_bucket(self):
        state = AttackState.objects.create(
            name="JSON State",
            current_phase="discovery",
            state_data={"target": "http://127.0.0.1:4280/"},
        )

        with override_settings(XPLOITAI_STATE_DIR=self.tmpdir.name):
            manager = StateManager(state.id)
            manager.record_phase_output(
                "discovery",
                action_name="EndpointDiscovery",
                status="SUCCESS",
                command="dirsearch -u http://127.0.0.1:4280/",
                command_id=7,
                target="http://127.0.0.1:4280/",
                stdout="FOUND /login",
                findings={"discovered_endpoints": ["/login"]},
                exit_code=0,
            )

            payload = json.loads(Path(manager.json_store.path).read_text(encoding="utf-8"))

        self.assertEqual(payload["target"], "http://127.0.0.1:4280/")
        self.assertEqual(payload["findings"]["discovered_endpoints"], ["/login"])
        scanning_outputs = payload["phase_outputs"]["scanning"]["outputs"]
        self.assertEqual(len(scanning_outputs), 1)
        self.assertEqual(scanning_outputs[0]["action_name"], "EndpointDiscovery")
        self.assertEqual(scanning_outputs[0]["stdout"], "FOUND /login")

    def test_planner_state_includes_local_phase_outputs(self):
        state = AttackState.objects.create(
            name="Planner Local State",
            current_phase="exploitation",
            state_data={"target": "http://dvwa.local"},
        )

        with override_settings(XPLOITAI_STATE_DIR=self.tmpdir.name):
            manager = StateManager(state.id)
            manager.update_state_with_findings(
                {"sqli_signals": ["id parameter appears injectable"]},
                phase_name="vulnerability_analysis",
            )
            planner_state = manager.get_current_state_for_planner()

        self.assertIn("phase_outputs", planner_state)
        self.assertEqual(
            planner_state["phase_outputs"]["scanning"]["findings"]["sqli_signals"],
            ["id parameter appears injectable"],
        )
        self.assertTrue(planner_state["local_state_file"].endswith(f"attack_state_{state.id}.json"))
