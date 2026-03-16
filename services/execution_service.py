import json
import logging
import threading
import time
import os

from ai.planner import AIPlanner
from executor.local_executor import run_command
from parser.output_parser import parse_output
from state.state_manager import StateManager
from core.models import AttackState

logger = logging.getLogger(__name__)


class ExecutionService:
    """
    Orchestrates the local, synchronous attack execution loop.
    Replaces the previous AutonomousController for this new architecture.
    """

    def __init__(self, attack_state_id: int, max_steps: int = 8, max_time_seconds: int = 300, max_retries: int = 1):
        self.attack_state_id = attack_state_id
        self.max_steps = max_steps
        self.max_time_seconds = max_time_seconds
        self.max_retries = max_retries
        self.state_manager = StateManager(attack_state_id=attack_state_id)
        self.planner = AIPlanner()
        self.command_map = self._load_json_file("actions/command_map.json")

    def _load_json_file(self, path: str) -> dict:
        try:
            with open(path, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Failed to load or parse {path}: {e}")
            return {}

    def start_assessment(self):
        """Starts the assessment in a background thread."""
        AttackState.objects.filter(id=self.attack_state_id).update(
            autonomy_status="RUNNING", stop_reason="Local execution started."
        )
        thread = threading.Thread(target=self._run_loop, daemon=True)
        thread.start()
        logger.info(f"Started local execution loop for AttackState {self.attack_state_id}")

    def _run_loop(self):
        """The main execution loop."""
        start_ts = time.time()

        for step in range(self.max_steps):
            elapsed = time.time() - start_ts
            if elapsed > self.max_time_seconds:
                self.stop_assessment(f"Maximum runtime exceeded ({self.max_time_seconds}s).")
                return

            logger.info(f"Execution loop step {step + 1}/{self.max_steps} for AttackState {self.attack_state_id} (elapsed {elapsed:.1f}s)")

            action_proposal = self.planner.get_next_action(self.state_manager)
            if not action_proposal:
                self.stop_assessment("Goal reached or no more actions possible.")
                return

            action_name = action_proposal["name"]
            action_params = action_proposal.get("parameters", {}) or {}
            action_reasoning = action_proposal.get("reasoning", "")

            if action_name not in self.command_map:
                self.stop_assessment(f"Action '{action_name}' is not permitted by command map.")
                return

            command_template = self.command_map.get(action_name)
            current_state = self.state_manager.get_current_state_for_planner()
            output_file = os.path.join("/tmp", f"xploitai_{self.attack_state_id}_{action_name}.txt")
            sub_context = {
                "target_url": current_state.get("target"),
                "target_host": current_state.get("target"),
                "target_domain": current_state.get("target"),
                "output_file": output_file,
                **action_params,
            }

            try:
                command = command_template.format(**sub_context)
            except KeyError as e:
                self.stop_assessment(f"Configuration error for action '{action_name}': missing {e}.")
                return

            result = None
            for attempt in range(self.max_retries + 1):
                result = run_command(command)
                self.state_manager.record_action(action_name, action_params, result, action_reasoning)

                if result.get("returncode") == 0:
                    break
                logger.warning(f"Action '{action_name}' failed (attempt {attempt + 1}/{self.max_retries + 1}).")
                if attempt < self.max_retries:
                    time.sleep(1)

            if not result:
                self.stop_assessment(f"Action '{action_name}' did not return a result.")
                return

            if result.get("returncode") == 0:
                output_to_parse = result.get("stdout", "")
                if "{output_file}" in command_template and os.path.exists(output_file):
                    with open(output_file, "r") as f:
                        output_to_parse = f.read()

                findings = parse_output(action_name, output_to_parse)
                if findings:
                    logger.info(f"Parsed findings for action '{action_name}': {findings}")
                    self.state_manager.update_state_with_findings(findings)
            else:
                logger.warning(f"Action '{action_name}' failed after retries. Skipping parsing.")

            time.sleep(2)

        self.stop_assessment(f"Maximum steps ({self.max_steps}) reached.")

    def stop_assessment(self, reason: str):
        logger.info(f"Stopping local execution for AttackState {self.attack_state_id}: {reason}")
        AttackState.objects.filter(id=self.attack_state_id).update(
            autonomy_status="STOPPED", stop_reason=reason
        )