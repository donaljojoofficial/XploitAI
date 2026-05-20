import json
import tempfile
from pathlib import Path

from django.test import TestCase, override_settings

from core.models import AttackState, Command, ExecutionResult, Phase
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

    def test_planner_state_merges_findings_from_phase_outputs_and_reviews(self):
        state = AttackState.objects.create(
            name="Planner Historical Findings",
            current_phase="exploitation",
            state_data={
                "target": "http://dvwa.local",
                "findings": {"identified_technologies": ["PHP"]},
                "level_history": [
                    {
                        "phase": "reconnaissance",
                        "findings": {"server_banner": "Apache"},
                        "details": {
                            "results_snapshot": [
                                {"findings": {"discovered_endpoints": ["/login"]}},
                            ],
                        },
                    },
                ],
            },
        )

        with override_settings(XPLOITAI_STATE_DIR=self.tmpdir.name):
            manager = StateManager(state.id)
            manager.record_phase_output(
                "vulnerability_analysis",
                action_name="VulnerabilityScanning",
                status="SUCCESS",
                findings={"exposed_paths": [{"path": "/phpinfo.php", "evidence": "PHP Version"}]},
            )
            planner_state = manager.get_current_state_for_planner()

        self.assertEqual(planner_state["findings"]["identified_technologies"], ["PHP"])
        self.assertEqual(planner_state["findings"]["server_banner"], "Apache")
        self.assertEqual(planner_state["findings"]["discovered_endpoints"], ["/login"])
        self.assertEqual(planner_state["findings"]["exposed_paths"][0]["path"], "/phpinfo.php")

    def test_planner_state_includes_compact_agent_memory(self):
        phase = Phase.objects.create(name="reconnaissance", description="Recon")
        command = Command.objects.create(
            phase=phase,
            name="HTTPHeaderFetch",
            description="Fetch headers",
            command_template="curl -I {target}",
        )
        state = AttackState.objects.create(
            name="Planner Memory",
            current_phase="discovery",
            state_data={
                "target": "http://dvwa.local",
                "findings": {"server_banner": "Apache"},
                "level_history": [
                    {
                        "phase": "reconnaissance",
                        "review": "Header fetch identified Apache.",
                        "details": {
                            "results_snapshot": [
                                {"command": "HTTPHeaderFetch", "status": "SUCCESS", "stdout_excerpt": "Server: Apache"},
                            ],
                        },
                    },
                ],
            },
        )
        ExecutionResult.objects.create(
            command=command,
            attack_state=state,
            target="http://dvwa.local",
            status="SUCCESS",
            stdout="Server: Apache\nX-Powered-By: PHP",
            findings={"identified_technologies": ["PHP"]},
        )

        with override_settings(XPLOITAI_STATE_DIR=self.tmpdir.name):
            manager = StateManager(state.id)
            manager.record_phase_output(
                "reconnaissance",
                action_name="HTTPHeaderFetch",
                status="SUCCESS",
                stdout="Server: Apache",
                findings={"server_banner": "Apache"},
            )
            planner_state = manager.get_current_state_for_planner()

        memory = planner_state["memory"]
        self.assertEqual(memory["target"], "http://dvwa.local")
        self.assertEqual(memory["findings"]["server_banner"], "Apache")
        self.assertEqual(memory["phase_summaries"][0]["last_action"], "HTTPHeaderFetch")
        self.assertEqual(memory["historical_reviews"][0]["phase"], "reconnaissance")
        self.assertEqual(memory["recent_results"][0]["action"], "HTTPHeaderFetch")
