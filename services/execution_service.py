import json
import logging
import threading
import time
import os

from ai.planner import AIPlanner
from ai.command_generator import CommandGenerator
from executor.local_executor import run_command
from parser.output_parser import (
    has_attack_completion_evidence,
    is_meaningful_action_success,
    parse_output,
)
from state.state_manager import StateManager
from core.models import AttackState, Command, ExecutionResult
from services.command_template_utils import (
    build_target_context,
    normalize_command_template,
    render_command_template,
)

logger = logging.getLogger(__name__)


class ExecutionService:
    """
    Orchestrates the local, synchronous attack execution loop.
    Replaces the previous AutonomousController for this new architecture.
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
                f"Execution loop step {step + 1}/{self.max_steps} for "
                f"AttackState {self.attack_state_id} (elapsed {elapsed:.1f}s)"
            )

            current_state = self.state_manager.get_current_state_for_planner()
            current_phase = current_state.get("current_phase", "reconnaissance")

            # Let the planner decide the next command AND handle phase advance.
            # Do NOT stop early because a phase has no remaining commands —
            # the planner will advance to the next phase and pick from there.
            decision = self.planner.get_next_command(self.state_manager)

            if not decision:
                # Planner returned None only when ALL phases are exhausted
                # or the kill-chain is genuinely complete.
                attack_state_obj = AttackState.objects.get(id=self.attack_state_id)
                if attack_state_obj.current_phase.upper() == "COMPLETED":
                    findings = ((attack_state_obj.state_data or {}).get("findings") or {})
                    if has_attack_completion_evidence(findings):
                        self.stop_assessment("Kill-chain completed successfully.")
                    else:
                        self.stop_assessment(
                            "Plan exhausted without exploitation or proof evidence."
                        )
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

            result = None
            final_status = "FAILED"
            for attempt in range(self.max_retries + 1):
                result = run_command(command)
                if result and result.get("returncode") == 0:
                    final_status = "SUCCESS"
                    break
                logger.warning(
                    f"Command '{command_obj.name}' (id={command_id}) failed "
                    f"(attempt {attempt + 1}/{self.max_retries + 1})."
                )
                if attempt < self.max_retries:
                    time.sleep(1)

            if not result:
                self.stop_assessment(f"Command '{command_obj.name}' returned no result.")
                return

            stdout = result.get("stdout", "")
            stderr = result.get("stderr", "")
            findings = {}
            if final_status == "SUCCESS":
                findings = parse_output(command_obj.name, stdout) or {}
                final_status = (
                    "SUCCESS"
                    if is_meaningful_action_success(command_obj.name, findings, stdout)
                    else "FAILED"
                )
                if findings:
                    logger.info(f"Parsed findings for '{command_obj.name}': {findings}")
                    self.state_manager.update_state_with_findings(findings)

            review_reason = self.planner.review_execution(
                self.state_manager,
                command_obj.name,
                command_parameters,
                final_status == "SUCCESS",
                stdout,
                stderr,
            )
            combined_reason = decision_reason if not review_reason else f"{decision_reason}\n\nAI review: {review_reason}"

            attack_state = AttackState.objects.get(id=self.attack_state_id)
            ExecutionResult.objects.create(
                command=command_obj,
                attack_state=attack_state,
                target=target,
                status=final_status,
                stdout=stdout,
                stderr=stderr,
                findings=findings,
            )

            self.state_manager.record_action(
                command_obj.name,
                command_parameters,
                result,
                combined_reason,
            )

            if final_status == "FAILED":
                logger.info(
                    "Command '%s' failed or produced no meaningful evidence; marking it unavailable and asking AI for another command for the same step.",
                    command_obj.name,
                )
                self.state_manager.add_completed_command(command_id)
                time.sleep(1)
                continue

            # Mark command complete only after a successful execution so the
            # next planned step cannot advance early.
            self.state_manager.add_completed_command(command_id)

            time.sleep(2)

        self.stop_assessment(f"Maximum steps ({self.max_steps}) reached.")

    def stop_assessment(self, reason: str):
        logger.info(f"Stopping local execution for AttackState {self.attack_state_id}: {reason}")
        AttackState.objects.filter(id=self.attack_state_id).update(
            autonomy_status="STOPPED", stop_reason=reason
        )
