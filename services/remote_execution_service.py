import json
import logging
import threading
import time
from typing import Any, Optional

from ai.planner import AIPlanner
from ai.command_generator import CommandGenerator
from ai.output_analysis import OutputAnalysisService
from core.models import AttackState, Command, ExecutionResult, ExecutionTask, AttackerExecutor
from core.levels import (
    DEFAULT_LEVEL_LIMITS,
    DEFAULT_STEP_MAX_RETRIES,
    DEFAULT_STEP_RETRY_COOLDOWN_SECONDS,
    build_runtime_profile,
    canonical_kill_chain_label,
    normalize_phase_name,
    parse_positive_int,
)
from state.state_manager import StateManager
from parser.output_parser import (
    has_attack_completion_evidence,
    is_meaningful_action_success,
    merge_findings,
    parse_output,
)
from services.command_template_utils import (
    build_target_context,
    infer_required_tools,
    is_probable_shell_command,
    normalize_command_targets,
    normalize_command_template,
    render_command_template,
    uses_disallowed_tool,
    uses_fragile_exploit_chain,
    uses_placeholder_loot_path,
)
from services.execution_failure_policy import is_terminal_command_failure
from services.script_runtime import (
    append_script_artifact,
    build_remote_script_command,
    build_script_artifact,
    is_script_step,
)
from services.tool_preflight import (
    RECOMMENDED_TOOL_INSTALL_COMMAND,
    TOOL_PREFLIGHT_TIMEOUT_SECONDS,
    command_result_summary,
    should_run_tool_preflight,
    update_tool_preflight_state,
)

logger = logging.getLogger(__name__)
DISABLE_COMMAND_TIMEOUTS_TEMPORARILY = True


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
        runtime_profile: Optional[dict[str, Any]] = None,
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
        self.output_analyzer = OutputAnalysisService()
        self.phase_command_counts = {}
        self.runtime_profile = build_runtime_profile(runtime_profile or {})
        state_data = (self.state_manager.get_attack_state().state_data or {})
        self.plan_command_lock = bool(state_data.get("plan_command_lock", True))

    def _remaining_runtime_budget(self, attack_state: AttackState) -> int:
        plan = attack_state.current_plan or {}
        runtime = plan.get("runtime") if isinstance(plan.get("runtime"), dict) else {}
        limits = plan.get("limits") if isinstance(plan.get("limits"), dict) else {}
        merged_limits = dict(DEFAULT_LEVEL_LIMITS)
        merged_limits.update(
            {
                key: parse_positive_int(limits.get(key, default), default)
                for key, default in DEFAULT_LEVEL_LIMITS.items()
            }
        )
        level_started_at = float(runtime.get("level_started_at") or time.time())
        elapsed = max(time.time() - level_started_at, 0.0)
        remaining_level = max(int(float(merged_limits["max_level_runtime_seconds"]) - elapsed), 30)
        remaining_service = max(int(self.max_time_seconds - elapsed), 30)
        return max(min(remaining_level, remaining_service), 30)

    def _step_timeout_seconds(self, attack_state: AttackState, action_name: str, command: str = "") -> int:
        if DISABLE_COMMAND_TIMEOUTS_TEMPORARILY:
            return 0

        action_token = str(action_name or "").strip().lower()
        command_text = str(command or "").strip().lower()
        preferred_timeout = 120

        if any(marker in command_text for marker in ("sqlmap", "hashcat", "john --wordlist")) or "sql" in action_token:
            preferred_timeout = 420
        elif any(marker in command_text for marker in ("nikto", "nuclei", "dirsearch", "theharvester", "dnsenum")):
            preferred_timeout = 300
        elif any(marker in command_text for marker in ("nmap", "wpscan", "msfconsole", "searchsploit")):
            preferred_timeout = 240
        elif "fingerprint" in action_token or "proof" in action_token:
            preferred_timeout = 180

        return max(30, min(preferred_timeout, self._remaining_runtime_budget(attack_state)))

    def _get_retry_config(self, step: dict | None) -> tuple[int, int]:
        step = step or {}
        max_retries = parse_positive_int(
            step.get("max_retries", self.runtime_profile.get("max_retries", DEFAULT_STEP_MAX_RETRIES)),
            DEFAULT_STEP_MAX_RETRIES,
        )
        cooldown = parse_positive_int(
            step.get("retry_cooldown_seconds", self.runtime_profile.get("retry_cooldown_seconds", DEFAULT_STEP_RETRY_COOLDOWN_SECONDS)),
            DEFAULT_STEP_RETRY_COOLDOWN_SECONDS,
        )
        return max_retries, cooldown

    def _find_plan_step(self, attack_state: AttackState, action_name: str) -> Optional[dict]:
        for step in (attack_state.current_plan or {}).get("steps") or []:
            step_name = step.get("action_type") or step.get("action")
            if step_name != action_name:
                continue
            if str(step.get("status") or "").lower() != "completed":
                return step
        return None

    def _record_level_runtime(self, *, success: bool) -> None:
        attack_state = AttackState.objects.get(id=self.attack_state_id)
        plan = attack_state.current_plan or {}
        runtime = plan.get("runtime") if isinstance(plan.get("runtime"), dict) else {}
        runtime["level_started_at"] = runtime.get("level_started_at") or time.time()
        runtime["total_attempts"] = int(runtime.get("total_attempts") or 0) + 1
        if not success:
            runtime["total_failures"] = int(runtime.get("total_failures") or 0) + 1
        runtime.setdefault("paused_by_limits", False)
        plan["runtime"] = runtime
        attack_state.current_plan = plan
        attack_state.save(update_fields=["current_plan"])

    def _level_limit_reason(self, attack_state: AttackState) -> Optional[str]:
        plan = attack_state.current_plan or {}
        runtime = plan.get("runtime") if isinstance(plan.get("runtime"), dict) else {}
        limits = plan.get("limits") if isinstance(plan.get("limits"), dict) else {}
        merged_limits = dict(DEFAULT_LEVEL_LIMITS)
        merged_limits.update(
            {
                key: parse_positive_int(limits.get(key, default), default)
                for key, default in DEFAULT_LEVEL_LIMITS.items()
            }
        )

        total_attempts = int(runtime.get("total_attempts") or 0)
        total_failures = int(runtime.get("total_failures") or 0)
        level_started_at = float(runtime.get("level_started_at") or time.time())
        elapsed = max(time.time() - level_started_at, 0.0)

        if total_attempts >= merged_limits["max_step_attempts_per_level"]:
            return f"Level rate limit reached: {total_attempts} attempts used."
        if total_failures >= merged_limits["max_level_failures"]:
            return f"Level failure cap reached: {total_failures} failed attempts."
        if elapsed >= float(merged_limits["max_level_runtime_seconds"]):
            return f"Level runtime cap reached: {int(elapsed)}s elapsed."
        return None

    def _persist_step_command(self, action_name: str, command: str):
        attack_state = AttackState.objects.get(id=self.attack_state_id)
        plan = attack_state.current_plan or {}
        steps = plan.get("steps") or []
        for step in steps:
            step_name = step.get("action_type") or step.get("action")
            if step_name == action_name and not step.get("resolved_command"):
                step["resolved_command"] = command
                step["resolved_tools"] = infer_required_tools(command)
                break
        attack_state.current_plan = plan
        attack_state.save(update_fields=["current_plan"])

    def _persist_script_artifact(self, action_name: str, artifact: dict) -> None:
        attack_state = AttackState.objects.get(id=self.attack_state_id)
        if not isinstance(attack_state.state_data, dict):
            attack_state.state_data = {}
        append_script_artifact(attack_state.state_data, artifact)

        plan = attack_state.current_plan or {}
        steps = plan.get("steps") or []
        for step in steps:
            step_name = step.get("action_type") or step.get("action")
            if step_name != action_name:
                continue
            refs = step.get("artifact_refs")
            if not isinstance(refs, list):
                refs = []
            refs.append(
                {
                    "id": artifact.get("id"),
                    "sha256": artifact.get("sha256"),
                    "type": artifact.get("type"),
                    "language": artifact.get("language"),
                }
            )
            step["artifact_refs"] = refs[-10:]
            break

        attack_state.current_plan = plan
        attack_state.save(update_fields=["state_data", "current_plan"])

    def _update_step_execution_state(
        self,
        action_name: str,
        *,
        status: str,
        command: str = "",
        command_id: int | None = None,
        command_retries: int = 0,
        stdout: str = "",
        stderr: str = "",
        findings: dict | None = None,
        schedule_retry: bool = False,
        next_allowed_at: float = 0,
        exit_code: int | None = None,
        script_artifact: dict | None = None,
    ) -> None:
        attack_state = AttackState.objects.get(id=self.attack_state_id)
        plan = attack_state.current_plan or {}
        steps = plan.get("steps") or []
        target_step = None

        for step in steps:
            step_name = step.get("action_type") or step.get("action")
            if step_name != action_name:
                continue
            if str(step.get("status") or "").lower() != "completed":
                target_step = step
                break

        if target_step is None:
            return

        target_step.setdefault("execution_history", [])
        target_step.setdefault("attempt_count", 0)
        target_step.setdefault("command_retry_count", 0)

        if command:
            target_step["resolved_command"] = command
            target_step["resolved_tools"] = infer_required_tools(command)
        if command_id:
            target_step["command_id"] = command_id

        normalized_status = str(status or "pending").lower()
        if normalized_status == "running":
            target_step["status"] = "running"
            target_step["cooldown_pending"] = False
        else:
            target_step["attempt_count"] = int(target_step.get("attempt_count") or 0) + 1
            target_step["command_retry_count"] = int(target_step.get("command_retry_count") or 0) + max(command_retries, 0)
            target_step["next_allowed_at"] = float(next_allowed_at or 0)
            if normalized_status == "success":
                target_step["status"] = "completed"
                target_step["alternative_pending"] = False
                target_step["cooldown_pending"] = False
            elif schedule_retry:
                target_step["status"] = "pending"
                target_step["alternative_pending"] = False
                target_step["cooldown_pending"] = True
            else:
                target_step["status"] = "failed"
                target_step["alternative_pending"] = True
                target_step["cooldown_pending"] = False
            target_step["last_output_excerpt"] = (stdout or "")[:400]
            target_step["last_error_excerpt"] = (stderr or "")[:240]
            target_step["last_exit_code"] = exit_code
            target_step["last_findings"] = findings or {}
            target_step["execution_history"].append(
                {
                    "attempt_number": target_step["attempt_count"],
                    "command_retry_count": max(command_retries, 0),
                    "command": command or target_step.get("resolved_command") or "",
                    "status": "SUCCESS" if normalized_status == "success" else ("RETRY_SCHEDULED" if schedule_retry else "FAILED"),
                    "stdout_excerpt": (stdout or "")[:400],
                    "stderr_excerpt": (stderr or "")[:240],
                    "exit_code": exit_code,
                    "findings": findings or {},
                    "next_allowed_at": float(next_allowed_at or 0),
                    "script_artifact_id": (script_artifact or {}).get("id"),
                    "script_sha256": (script_artifact or {}).get("sha256"),
                }
            )

        attack_state.current_plan = plan
        attack_state.save(update_fields=["current_plan"])

    def _store_phase_review_and_pause(self, current_phase: str) -> bool:
        attack_state = AttackState.objects.get(id=self.attack_state_id)
        next_phase = self.planner.peek_next_phase_with_commands(self.state_manager, attack_state)
        if not next_phase:
            return False

        review = self.planner.review_phase(self.state_manager, current_phase)
        if not isinstance(attack_state.state_data, dict):
            attack_state.state_data = {}
        reviews = attack_state.state_data.get("phase_reviews", [])
        if not isinstance(reviews, list):
            reviews = []
        level_history = attack_state.state_data.get("level_history", [])
        if not isinstance(level_history, list):
            level_history = []

        level_meta = (attack_state.current_plan or {}).get("level") if isinstance((attack_state.current_plan or {}).get("level"), dict) else {}
        if level_meta:
            level_meta["status"] = "completed"
        plan_runtime = (attack_state.current_plan or {}).get("runtime") if isinstance((attack_state.current_plan or {}).get("runtime"), dict) else {}
        review_item = (
            {
                "phase": current_phase,
                "review": (review or {}).get("summary", ""),
                "details": review or {},
                "next_phase": next_phase,
                "completed_at": time.time(),
                "findings": (attack_state.state_data.get("findings") or {}).copy(),
                "level": {
                    "index": level_meta.get("index"),
                    "phase_name": normalize_phase_name(current_phase),
                    "kill_chain_label": level_meta.get("kill_chain_label") or canonical_kill_chain_label(current_phase),
                },
                "metrics": {
                    "attempts": int(plan_runtime.get("total_attempts") or 0),
                    "failures": int(plan_runtime.get("total_failures") or 0),
                },
            }
        )
        reviews.append(review_item)
        level_history.append(review_item)
        attack_state.state_data["phase_reviews"] = reviews
        attack_state.state_data["level_history"] = level_history
        transition_payload = {
            "from_phase": current_phase,
            "to_phase": next_phase,
            "next_phase": next_phase,
            "review": review_item.get("review", ""),
            "key_evidence": ((review or {}).get("key_evidence") or []),
            "level": review_item.get("level", {}),
        }
        attack_state.state_data["phase_transition_pending"] = transition_payload
        attack_state.state_data["level_transition_pending"] = transition_payload
        attack_state.state_data["progression_mode"] = "manual"
        attack_state.state_data["plan_approved"] = False
        attack_state.current_phase = next_phase
        attack_state.current_plan = {}
        attack_state.save(update_fields=["state_data", "current_phase", "current_plan"])
        self.state_manager.record_phase_review(current_phase, review_item)

        plan_ready = self.planner.ensure_initial_plan(self.state_manager)
        attack_state.refresh_from_db()
        if not plan_ready or not (attack_state.current_plan or {}).get("steps"):
            self.stop_assessment(
                self.planner.last_plan_error
                or f"Phase '{current_phase}' reviewed, but next phase plan generation failed."
            )
            return True

        self.stop_assessment(
            f"Level '{current_phase}' reviewed. Plan for '{next_phase}' generated and waiting for approval."
        )
        return True

    def start_assessment(self):
        """Starts the remote execution in a background thread."""
        AttackState.objects.filter(id=self.attack_state_id).update(
            autonomy_status="RUNNING", stop_reason="Remote execution started."
        )
        thread = threading.Thread(target=self._run_loop, daemon=True)
        thread.start()
        logger.info(f"Started remote execution loop for AttackState {self.attack_state_id}")

    def _run_tool_preflight_if_requested(self) -> bool:
        attack_state = AttackState.objects.get(id=self.attack_state_id)
        if not should_run_tool_preflight(attack_state.state_data if isinstance(attack_state.state_data, dict) else {}):
            return True

        logger.info("Queueing recommended tool installation preflight for AttackState %s", self.attack_state_id)
        update_tool_preflight_state(attack_state, status="running")
        AttackState.objects.filter(id=self.attack_state_id).update(
            stop_reason="Installing recommended phase tools on remote executor before test commands..."
        )

        task = ExecutionTask.objects.create(
            action_name="ToolInstallPreflight",
            action=None,
            parameters={
                "command": RECOMMENDED_TOOL_INSTALL_COMMAND,
                "target": "",
                "reasoning": "Install recommended tools before running any generated phase commands.",
                "required_tools": ["apt-get", "sudo"],
                "execution_type": "command",
                "limits": {
                    "timeout": TOOL_PREFLIGHT_TIMEOUT_SECONDS,
                    "max_retries": 0,
                    "retry_cooldown_seconds": 0,
                },
            },
            status="PENDING",
            requires_approval=False,
        )

        result = self._wait_for_task_completion(task, timeout=TOOL_PREFLIGHT_TIMEOUT_SECONDS + 20)
        if not result:
            attack_state.refresh_from_db()
            update_tool_preflight_state(
                attack_state,
                status="failed",
                task_id=task.id,
                returncode=-1,
                stdout_excerpt="",
                stderr_excerpt="Recommended tool installation task timed out.",
            )
            self.stop_assessment("Recommended tool installation task timed out before test commands.")
            return False

        if isinstance(result.output, dict):
            output = result.output
            summary = command_result_summary(output)
            success = result.status == "COMPLETED" and output.get("returncode", 0) == 0
        else:
            summary = {
                "returncode": 0 if result.status == "COMPLETED" else 1,
                "stdout_excerpt": str(result.output or "")[-4000:],
                "stderr_excerpt": str(result.error_message or "")[-4000:],
            }
            success = result.status == "COMPLETED"

        attack_state.refresh_from_db()
        update_tool_preflight_state(
            attack_state,
            status="completed" if success else "failed",
            task_id=task.id,
            **summary,
        )

        if not success:
            self.stop_assessment(
                "Recommended tool installation failed before test commands. "
                "Use a Kali/Debian executor with apt-get and passwordless sudo, or start again without the install option."
            )
            return False

        return True

    def _create_remote_command_task(
        self,
        *,
        command_obj: Command,
        command: str,
        target: str,
        decision_reason: str,
        required_tools: list,
        execution_type: str,
        script_payload: dict,
        timeout_seconds: int,
        retry_budget: int,
        retry_cooldown: int,
    ) -> ExecutionTask:
        return ExecutionTask.objects.create(
            action_name=command_obj.name,
            action=None,
            parameters={
                "command": command,
                "target": target,
                "reasoning": decision_reason,
                "required_tools": required_tools or infer_required_tools(command),
                "execution_type": execution_type,
                "script": script_payload,
                "limits": {
                    "timeout": int(timeout_seconds),
                    "max_retries": int(retry_budget),
                    "retry_cooldown_seconds": int(retry_cooldown),
                    **((AttackState.objects.get(id=self.attack_state_id).current_plan or {}).get("limits") or {}),
                },
            },
            status="PENDING",
            requires_approval=False,
        )

    def _run_remote_command_parts(
        self,
        *,
        command_obj: Command,
        command: str,
        target: str,
        decision_reason: str,
        required_tools: list,
        execution_type: str,
        script_payload: dict,
        timeout_seconds: int,
        retry_budget: int,
        retry_cooldown: int,
    ) -> tuple[Optional[ExecutionTask], dict, list[str], list[int]]:
        task = self._create_remote_command_task(
            command_obj=command_obj,
            command=command,
            target=target,
            decision_reason=decision_reason,
            required_tools=required_tools,
            execution_type=execution_type,
            script_payload=script_payload,
            timeout_seconds=timeout_seconds,
            retry_budget=retry_budget,
            retry_cooldown=retry_cooldown,
        )
        logger.info(f"Created ExecutionTask {task.id} for command '{command_obj.name}'")
        result = self._wait_for_task_completion(task, timeout=0 if timeout_seconds <= 0 else timeout_seconds + 20)
        return task, {
            "task_result": result,
            "stdout": "",
            "stderr": "Task failed to complete within timeout." if not result else "",
            "returncode": -1 if not result else None,
            "status": getattr(result, "status", "FAILED"),
        }, [], []

    def _run_loop(self):
        """The main remote execution loop."""
        start_ts = time.time()
        attack_state = AttackState.objects.get(id=self.attack_state_id)

        if not self._run_tool_preflight_if_requested():
            return
        attack_state.refresh_from_db()

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
            attack_state.state_data.pop("auto_approve_generated_plan", None)
            if not attack_state.state_data.get("plan_approved", False):
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
            planned_command = (decision.get("planned_command") or "").strip()
            planned_tools = decision.get("required_tools") or []

            # Re-read current_phase after planner may have advanced it
            current_state = self.state_manager.get_current_state_for_planner()
            target = current_state.get("target") or ""
            sub_context = build_target_context(target)
            command_parameters = {**sub_context, **decision_parameters}
            attack_state_for_step = AttackState.objects.get(id=self.attack_state_id)
            step_state = self._find_plan_step(attack_state_for_step, command_obj.name)
            locked_step_command = (
                str((step_state or {}).get("resolved_command") or "").strip()
                if self.plan_command_lock
                else ""
            )

            try:
                if locked_step_command and uses_placeholder_loot_path(locked_step_command):
                    logger.warning(
                        "Ignoring placeholder loot command for '%s': %s",
                        command_obj.name,
                        locked_step_command,
                    )
                    generated = self.command_generator.generate(
                        command_obj.name,
                        command_parameters,
                    )
                    command = generated.shell_command
                elif locked_step_command and is_probable_shell_command(locked_step_command):
                    command = locked_step_command
                elif locked_step_command:
                    logger.warning(
                        "Ignoring non-shell resolved command for '%s': %s",
                        command_obj.name,
                        locked_step_command,
                    )
                    generated = self.command_generator.generate(
                        command_obj.name,
                        command_parameters,
                    )
                    command = generated.shell_command
                elif planned_command and uses_placeholder_loot_path(planned_command):
                    logger.warning(
                        "Ignoring placeholder loot planned command for '%s': %s",
                        command_obj.name,
                        planned_command,
                    )
                    generated = self.command_generator.generate(
                        command_obj.name,
                        command_parameters,
                    )
                    command = generated.shell_command
                elif planned_command and is_probable_shell_command(planned_command):
                    command = planned_command
                elif planned_command:
                    logger.warning(
                        "Ignoring non-shell planned command for '%s': %s",
                        command_obj.name,
                        planned_command,
                    )
                    generated = self.command_generator.generate(
                        command_obj.name,
                        command_parameters,
                    )
                    command = generated.shell_command
                else:
                    generated = self.command_generator.generate(
                        command_obj.name,
                        command_parameters,
                    )
                    command = generated.shell_command
                    if not str(command or "").strip():
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

            command = normalize_command_targets(command, command_parameters)
            if command_obj.name == "ExploitAttempt" and uses_fragile_exploit_chain(command):
                logger.warning(
                    "Replacing stale fragile exploit chain for '%s': %s",
                    command_obj.name,
                    command,
                )
                generated = self.command_generator.generate(command_obj.name, command_parameters)
                command = normalize_command_targets(generated.shell_command, command_parameters)
            if uses_disallowed_tool(command):
                logger.warning(
                    "Replacing disallowed tool command for '%s': %s",
                    command_obj.name,
                    command,
                )
                generated = self.command_generator.generate(
                    command_obj.name,
                    {**command_parameters, "disallowed_tools": ["arjun"]},
                )
                command = normalize_command_targets(generated.shell_command, command_parameters)
                if uses_disallowed_tool(command):
                    self.stop_assessment(
                        f"Planned step '{command_obj.name}' resolved to blocked tool 'arjun'. Regenerate this phase plan."
                    )
                    return
            self._persist_step_command(command_obj.name, command)
            attack_state_for_step = AttackState.objects.get(id=self.attack_state_id)
            step_state = self._find_plan_step(attack_state_for_step, command_obj.name)
            step_retry_budget = self.runtime_profile.get("max_retries", DEFAULT_STEP_MAX_RETRIES)
            step_retry_cooldown = self.runtime_profile.get("retry_cooldown_seconds", DEFAULT_STEP_RETRY_COOLDOWN_SECONDS)
            execution_type = "command"
            script_artifact = None
            if step_state:
                step_retry_budget, step_retry_cooldown = self._get_retry_config(step_state)
                step_state["max_retries"] = step_retry_budget
                step_state["retry_cooldown_seconds"] = step_retry_cooldown
                execution_type = "script" if is_script_step(step_state) else "command"
                next_allowed_at = float(step_state.get("next_allowed_at") or 0)
                if next_allowed_at > time.time():
                    wait_seconds = max(next_allowed_at - time.time(), 0.0)
                    logger.info(
                        "Step '%s' is in retry cooldown for %.1fs.",
                        command_obj.name,
                        wait_seconds,
                    )
                    time.sleep(min(wait_seconds, 1.0))
                    continue

            self._update_step_execution_state(
                command_obj.name,
                status="running",
                command=command,
                command_id=command_id,
            )

            step_timeout_seconds = self._step_timeout_seconds(attack_state_for_step, command_obj.name, command)
            command_for_task = command
            script_task_payload = {}
            if step_state and execution_type == "script":
                script_artifact = build_script_artifact(step_state, command_obj.name, command_id)
                self._persist_script_artifact(command_obj.name, script_artifact)
                command_for_task = build_remote_script_command(
                    script_content=script_artifact.get("content") or "",
                    script_language=step_state.get("script_language") or "python",
                )
                script_task_payload = {
                    "artifact_id": script_artifact.get("id"),
                    "script_sha256": script_artifact.get("sha256"),
                    "script_language": script_artifact.get("language"),
                }

            task, remote_payload, command_parts, part_returncodes = self._run_remote_command_parts(
                command_obj=command_obj,
                command=command_for_task,
                target=target,
                decision_reason=decision_reason,
                required_tools=planned_tools or infer_required_tools(command_for_task),
                execution_type=execution_type,
                script_payload=script_task_payload,
                timeout_seconds=step_timeout_seconds,
                retry_budget=step_retry_budget,
                retry_cooldown=step_retry_cooldown,
            )

            result = remote_payload.get("task_result")
            if not result:
                result = type(
                    "RemoteResult",
                    (),
                    {
                        "status": remote_payload.get("status", "FAILED"),
                        "output": {
                            "stdout": remote_payload.get("stdout", ""),
                            "stderr": remote_payload.get("stderr", ""),
                            "returncode": remote_payload.get("returncode", -1),
                            "part_returncodes": part_returncodes,
                        },
                        "error_message": remote_payload.get("stderr", ""),
                    },
                )()

            # Process the result
            if result.status == "COMPLETED":
                output = result.output if isinstance(result.output, dict) else {}
                stdout = output.get("stdout", "") if output else (result.output or "")
                stderr = output.get("stderr", "") if output else result.error_message
                terminal_failure = is_terminal_command_failure(output, stderr)
                findings = parse_output(command_obj.name, stdout)
                findings = merge_findings(
                    findings,
                    self.output_analyzer.analyze(
                        command_obj.name,
                        stdout,
                        stderr,
                        current_state.get("findings", {}),
                    ),
                )
                semantic_success = is_meaningful_action_success(
                    command_obj.name,
                    findings,
                    stdout,
                )
                if findings:
                    logger.info(f"Parsed findings for '{command_obj.name}': {findings}")
                    self.state_manager.update_state_with_findings(
                        findings,
                        phase_name=current_state.get("current_phase"),
                    )

                should_retry = False
                scheduled_retry_count = 0
                next_retry_at = 0.0
                if not semantic_success:
                    attack_state_for_retry = AttackState.objects.get(id=self.attack_state_id)
                    retry_step = self._find_plan_step(attack_state_for_retry, command_obj.name)
                    max_retries, retry_cooldown = self._get_retry_config(retry_step or {})
                    retries_used = int((retry_step or {}).get("command_retry_count") or 0)
                    semantic_no_evidence = output.get("returncode", 0) == 0
                    should_retry = (not terminal_failure) and (not semantic_no_evidence) and retries_used < max_retries
                    if should_retry:
                        scheduled_retry_count = 1
                        next_retry_at = time.time() + float(retry_cooldown)
                    elif terminal_failure:
                        logger.info(
                            "Remote command '%s' failed terminally; skipping retries and asking for an alternative.",
                            command_obj.name,
                        )
                    elif semantic_no_evidence:
                        logger.info(
                            "Remote command '%s' completed without useful evidence; asking for an alternative.",
                            command_obj.name,
                        )

                self._update_step_execution_state(
                    command_obj.name,
                    status="SUCCESS" if semantic_success else "FAILED",
                    command=command_for_task,
                    command_id=command_id,
                    command_retries=scheduled_retry_count,
                    stdout=stdout,
                    stderr=stderr,
                    findings=findings,
                    schedule_retry=should_retry,
                    next_allowed_at=next_retry_at,
                    exit_code=output.get("returncode") if isinstance(output, dict) else (0 if semantic_success else 1),
                    script_artifact=script_artifact,
                )
                self._record_level_runtime(success=semantic_success)
                refreshed_for_limits = AttackState.objects.get(id=self.attack_state_id)
                limit_reason = self._level_limit_reason(refreshed_for_limits)
                if limit_reason:
                    plan = refreshed_for_limits.current_plan or {}
                    runtime = plan.get("runtime") if isinstance(plan.get("runtime"), dict) else {}
                    runtime["paused_by_limits"] = True
                    plan["runtime"] = runtime
                    refreshed_for_limits.current_plan = plan
                    refreshed_for_limits.save(update_fields=["current_plan"])
                    self.stop_assessment(limit_reason)
                    return

                review_reason = self.planner.review_execution(
                    self.state_manager,
                    command_obj.name,
                    command_parameters,
                    semantic_success,
                    stdout,
                    stderr,
                )
                combined_reason = decision_reason if not review_reason else f"{decision_reason}\n\nAI review: {review_reason}"

                # Create ExecutionResult record
                attack_state = AttackState.objects.get(id=self.attack_state_id)
                persisted_findings = dict(findings or {})
                if script_artifact:
                    persisted_findings.setdefault(
                        "script_execution",
                        {
                            "artifact_id": script_artifact.get("id"),
                            "sha256": script_artifact.get("sha256"),
                            "language": script_artifact.get("language"),
                            "exit_code": output.get("returncode") if isinstance(output, dict) else (0 if semantic_success else 1),
                        },
                    )
                ExecutionResult.objects.create(
                    command=command_obj,
                    attack_state=attack_state,
                    target=target,
                    status="SUCCESS" if semantic_success else "FAILED",
                    stdout=stdout,
                    stderr=stderr,
                    findings=persisted_findings,
                )
                self.state_manager.record_phase_output(
                    current_state.get("current_phase") or attack_state.current_phase,
                    action_name=command_obj.name,
                    status="SUCCESS" if semantic_success else "FAILED",
                    command=command_for_task,
                    command_id=command_id,
                    target=target,
                    stdout=stdout,
                    stderr=stderr,
                    findings=persisted_findings,
                    exit_code=output.get("returncode") if isinstance(output, dict) else (0 if semantic_success else 1),
                    metadata={"execution_mode": "remote", "task_id": task.id},
                )

                self.state_manager.record_action(
                    command_obj.name,
                    command_parameters,
                    {"stdout": stdout, "stderr": stderr, "returncode": 0 if semantic_success else 1},
                    combined_reason,
                )

                attack_state.refresh_from_db()
                if self.planner.current_phase_completed(attack_state):
                    current_phase_name = (attack_state.current_plan or {}).get("phase") or attack_state.current_phase
                    if self._store_phase_review_and_pause(current_phase_name):
                        return

                if semantic_success:
                    # Mark command complete only after a successful execution so the
                    # next planned step cannot advance early.
                    self.state_manager.add_completed_command(command_id)
                else:
                    if should_retry:
                        logger.info(
                            "Command '%s' did not produce semantic success; retry scheduled with cooldown.",
                            command_obj.name,
                        )
                        time.sleep(1)
                        continue
                    logger.info(
                        "Command '%s' ran but produced no exploit/proof evidence; asking AI for another command for the same step.",
                        command_obj.name,
                    )
                    self.state_manager.add_completed_command(command_id)
                    time.sleep(1)
                    continue
            else:
                output = result.output if isinstance(result.output, dict) else {}
                stdout = output.get("stdout", "") if output else (result.output or "")
                stderr = output.get("stderr", "") if output else result.error_message
                terminal_failure = is_terminal_command_failure(output, stderr or result.error_message or "")
                logger.warning(f"Task {task.id} failed: {result.error_message}")
                findings = merge_findings(
                    parse_output(command_obj.name, stdout) or {},
                    self.output_analyzer.analyze(
                        command_obj.name,
                        stdout,
                        stderr or result.error_message or "",
                        current_state.get("findings", {}),
                    ),
                )
                if findings:
                    logger.info(f"Parsed findings for failed '{command_obj.name}': {findings}")
                    self.state_manager.update_state_with_findings(
                        findings,
                        phase_name=current_state.get("current_phase"),
                    )
                should_retry = False
                scheduled_retry_count = 0
                next_retry_at = 0.0
                attack_state_for_retry = AttackState.objects.get(id=self.attack_state_id)
                retry_step = self._find_plan_step(attack_state_for_retry, command_obj.name)
                max_retries, retry_cooldown = self._get_retry_config(retry_step or {})
                retries_used = int((retry_step or {}).get("command_retry_count") or 0)
                should_retry = (not terminal_failure) and retries_used < max_retries
                if should_retry:
                    scheduled_retry_count = 1
                    next_retry_at = time.time() + float(retry_cooldown)
                elif terminal_failure:
                    logger.info(
                        "Remote command '%s' failed terminally; skipping retries and asking for an alternative.",
                        command_obj.name,
                    )

                self._update_step_execution_state(
                    command_obj.name,
                    status="FAILED",
                    command=command_for_task,
                    command_id=command_id,
                    command_retries=scheduled_retry_count,
                    stdout=stdout,
                    stderr=stderr or result.error_message or "",
                    findings=findings,
                    schedule_retry=should_retry,
                    next_allowed_at=next_retry_at,
                    exit_code=output.get("returncode") if isinstance(output, dict) else 1,
                    script_artifact=script_artifact,
                )
                self._record_level_runtime(success=False)
                refreshed_for_limits = AttackState.objects.get(id=self.attack_state_id)
                limit_reason = self._level_limit_reason(refreshed_for_limits)
                if limit_reason:
                    plan = refreshed_for_limits.current_plan or {}
                    runtime = plan.get("runtime") if isinstance(plan.get("runtime"), dict) else {}
                    runtime["paused_by_limits"] = True
                    plan["runtime"] = runtime
                    refreshed_for_limits.current_plan = plan
                    refreshed_for_limits.save(update_fields=["current_plan"])
                    self.stop_assessment(limit_reason)
                    return
                review_reason = self.planner.review_execution(
                    self.state_manager,
                    command_obj.name,
                    command_parameters,
                    False,
                    stdout,
                    stderr or result.error_message or "",
                )
                combined_reason = decision_reason if not review_reason else f"{decision_reason}\n\nAI review: {review_reason}"

                attack_state = AttackState.objects.get(id=self.attack_state_id)
                persisted_findings = dict(findings or {})
                if script_artifact:
                    persisted_findings.setdefault(
                        "script_execution",
                        {
                            "artifact_id": script_artifact.get("id"),
                            "sha256": script_artifact.get("sha256"),
                            "language": script_artifact.get("language"),
                            "exit_code": output.get("returncode") if isinstance(output, dict) else 1,
                        },
                    )
                ExecutionResult.objects.create(
                    command=command_obj,
                    attack_state=attack_state,
                    target=target,
                    status="FAILED",
                    stdout=stdout,
                    stderr=stderr or result.error_message or "",
                    findings=persisted_findings,
                )
                self.state_manager.record_phase_output(
                    current_state.get("current_phase") or attack_state.current_phase,
                    action_name=command_obj.name,
                    status="FAILED",
                    command=command_for_task,
                    command_id=command_id,
                    target=target,
                    stdout=stdout,
                    stderr=stderr or result.error_message or "",
                    findings=persisted_findings,
                    exit_code=output.get("returncode") if isinstance(output, dict) else 1,
                    metadata={"execution_mode": "remote", "task_id": task.id},
                )

                self.state_manager.record_action(
                    command_obj.name,
                    command_parameters,
                    {"stdout": stdout, "stderr": stderr or result.error_message or "", "returncode": 1},
                    combined_reason,
                )

                attack_state.refresh_from_db()
                if self.planner.current_phase_completed(attack_state):
                    current_phase_name = (attack_state.current_plan or {}).get("phase") or attack_state.current_phase
                    if self._store_phase_review_and_pause(current_phase_name):
                        return

                logger.info(
                    "Command '%s' failed; marking it unavailable and asking AI for another command for the same step.",
                    command_obj.name,
                )
                if should_retry:
                    logger.info(
                        "Command '%s' failed remotely; retry scheduled with cooldown.",
                        command_obj.name,
                    )
                    time.sleep(1)
                    continue
                self.state_manager.add_completed_command(command_id)
                time.sleep(1)
                continue

            time.sleep(2)  # Brief pause between tasks

        self.stop_assessment(f"Maximum steps ({self.max_steps}) reached.")

    def _wait_for_task_completion(self, task: ExecutionTask, timeout: int = 60) -> Optional[ExecutionTask]:
        """Wait for a task to be completed by a remote executor."""
        start_time = time.time()

        while timeout <= 0 or time.time() - start_time < timeout:
            task.refresh_from_db()
            if task.status in ["COMPLETED", "FAILED", "TIMEOUT"]:
                return task
            time.sleep(1)

        task.refresh_from_db()
        if task.status in {"PENDING", "RUNNING"}:
            task.status = "FAILED"
            task.output = {
                "stdout": "",
                "stderr": f"Controller wait timed out after {int(timeout)}s. The executor should terminate the remote process via its command timeout.",
                "returncode": -1,
                "error": "TimeoutExpired",
            }
            task.error_message = task.output["stderr"]
            task.save(update_fields=["status", "output", "error_message"])
            return task
        return None

    def stop_assessment(self, reason: str):
        logger.info(f"Stopping remote execution for AttackState {self.attack_state_id}: {reason}")
        AttackState.objects.filter(id=self.attack_state_id).update(
            autonomy_status="STOPPED", stop_reason=reason
        )
