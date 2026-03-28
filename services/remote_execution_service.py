import json
import logging
import threading
import time
from typing import Optional

from ai.planner import AIPlanner
from ai.command_generator import CommandGenerator
from core.models import AttackState, Command, ExecutionResult, ExecutionTask, AttackerExecutor
from state.state_manager import StateManager
from parser.output_parser import parse_output
from services.command_template_utils import (
    build_target_context,
    infer_required_tools,
    normalize_command_template,
    render_command_template,
)

logger = logging.getLogger(__name__)


class RemoteExecutionService:
    """
    Orchestrates remote attack execution using external executors.
    Works with the executor daemon system for distributed execution.
    """

    def __init__(
        self,
        attack_state_id: int,
        max_steps: int = 10,
        max_time_seconds: int = 120,
        max_retries: int = 1,
        max_commands_per_phase: int = 3,
        llm_provider: str = "auto",
    ):
        self.attack_state_id = attack_state_id
        self.max_steps = max_steps
        self.max_time_seconds = max_time_seconds
        self.max_retries = max_retries
        self.max_commands_per_phase = max_commands_per_phase
        self.state_manager = StateManager(attack_state_id=attack_state_id)
        self.planner = AIPlanner(provider=llm_provider)
        self.llm_provider = (llm_provider or "auto").lower()
        self.command_generator = CommandGenerator(
            use_llm=self.llm_provider == "hybrid",
            llm_provider="groq" if self.llm_provider == "hybrid" else llm_provider,
        )
        self.phase_command_counts = {}

    def start_assessment(self):
        """Starts the remote execution in a background thread."""
        AttackState.objects.filter(id=self.attack_state_id).update(
            autonomy_status="RUNNING", stop_reason="Remote execution started."
        )
        thread = threading.Thread(target=self._run_loop, daemon=True)
        thread.start()
        logger.info(f"Started remote execution loop for AttackState {self.attack_state_id}")

    def _run_loop(self):
        """The main remote execution loop."""
        start_ts = time.time()
        attack_state = AttackState.objects.get(id=self.attack_state_id)

        if not (attack_state.current_plan or {}).get("steps"):
            AttackState.objects.filter(id=self.attack_state_id).update(
                autonomy_status="PLANNING",
                stop_reason="Generating strategic plan...",
            )
            plan_ready = self.planner.ensure_initial_plan(self.state_manager)
            attack_state.refresh_from_db()
            if not plan_ready or not (attack_state.current_plan or {}).get("steps"):
                self.stop_assessment(
                    self.planner.last_plan_error or "Plan generation failed."
                )
                return

            if not isinstance(attack_state.state_data, dict):
                attack_state.state_data = {}
            attack_state.state_data["plan_approved"] = False
            attack_state.save(update_fields=["state_data"])
            self.stop_assessment("Plan generated. Waiting for approval.")
            return

        if not (attack_state.state_data or {}).get("plan_approved", False):
            self.stop_assessment("Plan generated. Waiting for approval.")
            return

        for step in range(self.max_steps):
            elapsed = time.time() - start_ts
            if elapsed > self.max_time_seconds:
                self.stop_assessment(f"Maximum runtime exceeded ({self.max_time_seconds}s).")
                return

            logger.info(
                f"Remote execution loop step {step + 1}/{self.max_steps} for "
                f"AttackState {self.attack_state_id} (elapsed {elapsed:.1f}s)"
            )

            current_state = self.state_manager.get_current_state_for_planner()
            current_phase = current_state.get("current_phase", "reconnaissance")

            # Let the planner decide the next command AND handle phase advance.
            decision = self.planner.get_next_command(self.state_manager)

            if not decision:
                # Planner returned None only when ALL phases are exhausted
                attack_state_obj = AttackState.objects.get(id=self.attack_state_id)
                if attack_state_obj.current_phase.upper() == "COMPLETED":
                    self.stop_assessment("Kill-chain completed successfully.")
                else:
                    self.stop_assessment(
                        f"No commands available across all remaining phases "
                        f"(current: {attack_state_obj.current_phase})."
                    )
                return

            command_id = decision.get("command_id")
            decision_reason = decision.get("reason", "No reason provided.")
            decision_parameters = decision.get("parameters") or {}

            command_obj = Command.objects.filter(id=command_id).first()
            if not command_obj:
                self.stop_assessment(f"Selected command_id {command_id} not found.")
                return

            command_template = normalize_command_template(command_obj)

            # Re-read current_phase after planner may have advanced it
            current_state = self.state_manager.get_current_state_for_planner()
            target = current_state.get("target") or ""
            sub_context = build_target_context(target)
            command_parameters = {**sub_context, **decision_parameters}

            try:
                if self.llm_provider == "hybrid":
                    generated = self.command_generator.generate(
                        command_obj.name,
                        command_parameters,
                    )
                    command = generated.shell_command
                else:
                    command = render_command_template(command_template, sub_context)
            except KeyError as e:
                logger.warning(
                    f"Command template for '{command_obj.name}' missing placeholder {e}. "
                    "Stopping because the planned step cannot be executed."
                )
                self.stop_assessment(
                    f"Planned step '{command_obj.name}' could not be rendered: missing placeholder {e}."
                )
                return

            # Create an ExecutionTask for the remote executor to pick up
            task = ExecutionTask.objects.create(
                action_name=command_obj.name,
                action=None,  # No high-level action for remote execution
                parameters={
                    "command": command,
                    "target": target,
                    "reasoning": decision_reason,
                    "required_tools": infer_required_tools(command),
                },
                status="PENDING",
                requires_approval=False,  # Remote execution doesn't require approval in this phase
            )

            logger.info(f"Created ExecutionTask {task.id} for command '{command_obj.name}'")

            # Wait for the task to be completed by the remote executor
            result = self._wait_for_task_completion(task)
            
            if not result:
                self.stop_assessment(f"Task {task.id} failed to complete within timeout.")
                return

            # Process the result
            if result.status == "COMPLETED":
                output = result.output if isinstance(result.output, dict) else {}
                stdout = output.get("stdout", "") if output else (result.output or "")
                stderr = output.get("stderr", "") if output else result.error_message
                
                findings = parse_output(command_obj.name, stdout)
                if findings:
                    logger.info(f"Parsed findings for '{command_obj.name}': {findings}")
                    self.state_manager.update_state_with_findings(findings)

                review_reason = self.planner.review_execution(
                    self.state_manager,
                    command_obj.name,
                    command_parameters,
                    True,
                    stdout,
                    stderr,
                )
                combined_reason = decision_reason if not review_reason else f"{decision_reason}\n\nNVIDIA review: {review_reason}"

                # Create ExecutionResult record
                attack_state = AttackState.objects.get(id=self.attack_state_id)
                ExecutionResult.objects.create(
                    command=command_obj,
                    attack_state=attack_state,
                    target=target,
                    status="SUCCESS",
                    stdout=stdout,
                    stderr=stderr,
                    findings=findings or {},
                )

                self.state_manager.record_action(
                    command_obj.name,
                    command_parameters,
                    {"stdout": stdout, "stderr": stderr, "returncode": 0},
                    combined_reason,
                )

                # Mark command complete only after a successful execution so the
                # next planned step cannot advance early.
                self.state_manager.add_completed_command(command_id)
            else:
                output = result.output if isinstance(result.output, dict) else {}
                stdout = output.get("stdout", "") if output else (result.output or "")
                stderr = output.get("stderr", "") if output else result.error_message
                logger.warning(f"Task {task.id} failed: {result.error_message}")
                review_reason = self.planner.review_execution(
                    self.state_manager,
                    command_obj.name,
                    command_parameters,
                    False,
                    stdout,
                    stderr or result.error_message or "",
                )
                combined_reason = decision_reason if not review_reason else f"{decision_reason}\n\nNVIDIA review: {review_reason}"

                attack_state = AttackState.objects.get(id=self.attack_state_id)
                ExecutionResult.objects.create(
                    command=command_obj,
                    attack_state=attack_state,
                    target=target,
                    status="FAILED",
                    stdout=stdout,
                    stderr=stderr or result.error_message or "",
                    findings={},
                )

                self.state_manager.record_action(
                    command_obj.name,
                    command_parameters,
                    {"stdout": stdout, "stderr": stderr or result.error_message or "", "returncode": 1},
                    combined_reason,
                )

                logger.info(
                    "Command '%s' failed; marking it unavailable and asking AI for another command for the same step.",
                    command_obj.name,
                )
                self.state_manager.add_completed_command(command_id)
                time.sleep(1)
                continue

            time.sleep(2)  # Brief pause between tasks

        self.stop_assessment(f"Maximum steps ({self.max_steps}) reached.")

    def _wait_for_task_completion(self, task: ExecutionTask, timeout: int = 60) -> Optional[ExecutionTask]:
        """Wait for a task to be completed by a remote executor."""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            task.refresh_from_db()
            if task.status in ["COMPLETED", "FAILED", "TIMEOUT"]:
                return task
            time.sleep(1)
        
        return None

    def stop_assessment(self, reason: str):
        logger.info(f"Stopping remote execution for AttackState {self.attack_state_id}: {reason}")
        AttackState.objects.filter(id=self.attack_state_id).update(
            autonomy_status="STOPPED", stop_reason=reason
        )
