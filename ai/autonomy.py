"""
Autonomous AI Control Loop — XploitAI

Responsibilities:
- Orchestrate the AI decision -> policy -> execution cycle.
- Manage the autonomous loop state (start/stop).
- Interface with the ExecutionTask queue.

This module implements the high-level control logic that drives the
autonomous behavior of the system in Phase 2.
"""

from __future__ import annotations

import datetime
import json
import logging
import re
import uuid
import threading
import time
from typing import Optional

from django.db import transaction
from django.utils import timezone

from core.models import Action, AttackState, ExecutionTask, DefenderAlert, AttackContext, ActionResult, AttackTimelineEvent, KILL_CHAIN_PHASES
# Use the concrete implementation from agent.decision
from ai.decision_engine import DecisionEngine
from ai.command_generator import CommandGenerator
from ai.context_manager import OperationalContextManager
from ai.safety import CommandSafety
from policy.engine import PolicyEngine

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("ai_audit")


class AutonomousController:
    """
    Controller for the autonomous AI execution loop.

    This class acts as the central nervous system for the autonomous mode.
    It does not make decisions itself but coordinates the components that do.
    """

    def __init__(
        self,
        attack_state_id: int,
        max_steps: int = 50,
        max_consecutive_failures: int = 3,
        llm_provider: str = "auto"
    ) -> None:
        self.attack_state_id = attack_state_id
        self.running = False
        self.max_steps = max_steps
        self.max_consecutive_failures = max_consecutive_failures
        self.step_count = 0
        self.llm_provider = llm_provider

        # Initialize components
        self.decision_engine = DecisionEngine(provider=llm_provider)
        self.policy_engine = PolicyEngine()
        self.command_generator = CommandGenerator(use_llm=False, llm_provider=llm_provider)
        self.safety_filter = CommandSafety()

    def start(self) -> None:
        """Start the autonomous control loop."""
        # OPS-8: Validate Operational Context before starting
        try:
            context = OperationalContextManager.ensure_running_context()
        except RuntimeError as e:
            logger.error("Cannot start autonomy: %s", e)
            AttackState.objects.filter(id=self.attack_state_id).update(
                autonomy_status="STOPPED", stop_reason=f"Context Error: {e}"
            )
            return

        # OPS-10: Update Context Start
        # Transition from READY to RUNNING and log start time
        if context.status == AttackContext.Status.READY:
            context.status = AttackContext.Status.RUNNING
            context.started_at = timezone.now()
            context.save(update_fields=['status', 'started_at'])

        self.running = True
        self.step_count = 0
        
        # Sync state to DB
        AttackState.objects.filter(id=self.attack_state_id).update(
            autonomy_status="RUNNING", stop_reason="", current_plan={}
        )
        logger.info("AutonomousController started for AttackState ID %s", self.attack_state_id)

        # Trigger the planner loop in a background thread
        threading.Thread(target=self._autonomy_loop, daemon=True).start()

    def request_initial_plan(self) -> None:
        """
        Starts a background thread to generate the initial plan without starting the full loop.
        Transitions state to PLANNING -> STOPPED (Waiting for approval).
        """
        def _plan_task():
            try:
                state = AttackState.objects.get(id=self.attack_state_id)
                
                # Update status to indicate work in progress
                state.autonomy_status = "PLANNING"
                state.stop_reason = "Generating strategic plan..."
                state.save(update_fields=['autonomy_status', 'stop_reason'])
                
                # Sync context required for planning
                self._sync_planner_context(state)
                self._sync_defender_context(state)
                
                # Generate the plan
                plan = self.decision_engine.generate_plan(state)
                
                if plan:
                    if not state.state_data:
                        state.state_data = {}
                    state.state_data['plan_approved'] = False
                    state.stop_reason = "Plan generated. Waiting for approval."
                    state.autonomy_status = "STOPPED"
                else:
                    state.stop_reason = "Plan generation failed."
                    state.autonomy_status = "STOPPED"
                
                state.save()
            except Exception as e:
                logger.error(f"Initial planning failed: {e}")
                AttackState.objects.filter(id=self.attack_state_id).update(
                    autonomy_status="STOPPED", stop_reason=f"Planning error: {e}"
                )

        threading.Thread(target=_plan_task, daemon=True).start()

    def stop(self, reason: str = "Manual Stop") -> None:
        """Stop the autonomous control loop."""
        self.running = False
        
        # Sync state to DB
        AttackState.objects.filter(id=self.attack_state_id).update(
            autonomy_status="STOPPED", stop_reason=reason
        )

        # OPS-10: Log context stop
        # Transition active context to STOPPED and log reason
        context = OperationalContextManager.get_active_context()
        if context:
            context.status = AttackContext.Status.STOPPED
            context.stopped_at = timezone.now()
            context.stop_reason = reason
            context.save(update_fields=['status', 'stopped_at', 'stop_reason'])

        logger.info("AutonomousController stopped for AttackState ID %s. Reason: %s", 
                    self.attack_state_id, reason)

    def _autonomy_loop(self) -> None:
        """
        Background loop to drive autonomy.
        Checks DB state to ensure it should keep running.
        """
        logger.info("PLANNER LOOP ENTERED (Threaded) for AttackState %s", self.attack_state_id)
        while self.running:
            # Verify we are still supposed to be running according to DB
            try:
                status = AttackState.objects.values_list('autonomy_status', flat=True).get(id=self.attack_state_id)
                if status != 'RUNNING':
                    self.running = False
                    break
            except AttackState.DoesNotExist:
                self.running = False
                break

            try:
                self.run_cycle()
            except Exception as e:
                logger.exception("Unexpected error in autonomy cycle: %s", e)
                self.stop(reason=f"Internal Error: {e}")
                break

            time.sleep(2)  # Polling interval to prevent busy loop

    def run_cycle(self) -> bool:
        """
        Execute a single step of the autonomous loop.

        Flow:
        1. Check if running.
        2. Sync execution status from tasks to actions.
        3. Check stop conditions (max steps, failures).
        4. Check for pending tasks (wait if busy).
        5. Get AI decision.
        6. Validate with Policy.
        7. Queue ExecutionTask.

        Returns:
            bool: True if a task was queued, False otherwise (waiting or stopped).
        """
        cycle_id = str(uuid.uuid4())
        self._log_audit(cycle_id, "CYCLE_START", {"step_count": self.step_count})

        if not self.running:
            return False

        try:
            state = AttackState.objects.get(id=self.attack_state_id)
        except AttackState.DoesNotExist:
            logger.error("AttackState %s not found. Stopping controller.", self.attack_state_id)
            self.stop(reason="AttackState not found")
            return False

        # 1. Sync Action states with ExecutionTasks
        self._sync_action_states(state)

        # 2. Sync Defender Context (Alerts -> State)
        self._sync_defender_context(state)

        # Sync Planner Context (Goal/Target -> State)
        self._sync_planner_context(state)

        # Sync Execution History (Results -> State)
        self._sync_execution_history(state)

        # 3. Check Stop Conditions
        stop_reason = self._check_stop_conditions(state)
        if stop_reason:
            self._log_audit(cycle_id, "CYCLE_STOPPED", {"reason": stop_reason})
            self.stop(reason=stop_reason)
            return False

        # 4. Wait for execution results
        if self._has_pending_tasks():
            self._log_audit(cycle_id, "CYCLE_WAITING", {"reason": "Pending tasks"})
            logger.debug("Pending tasks detected. Waiting for execution.")
            return False

        # 5. Get AI Decision
        # We request 1 proposal for the autonomous loop
        proposals = self.decision_engine.generate_actions(state)
        if not proposals:
            # Check if waiting for approval
            if state.current_plan and not (state.state_data or {}).get('plan_approved', False):
                reason = "Plan generated. Waiting for approval."
                self._log_audit(cycle_id, "CYCLE_STOPPED", {"reason": reason})
                logger.info("Stopping autonomy: %s", reason)
                self.stop(reason=reason)
                return False

            reason = "No proposals returned (Goal reached or stuck)"
            self._log_audit(cycle_id, "CYCLE_STOPPED", {"reason": reason})
            logger.info("Decision Engine returned no proposals. Goal reached or stuck. Stopping.")
            self.stop(reason=reason)
            return False

        proposal = proposals[0]
        self._log_audit(cycle_id, "AI_PROPOSAL", {
            "name": proposal.name,
            "score": getattr(proposal, 'score', 1.0),
            "params": proposal.parameters
        })

        # 5.5 Loop Prevention: Check for repetitive actions
        if self._is_repetitive_action(state, proposal):
            self._log_audit(cycle_id, "ACTION_BLOCKED", {"reason": "Repetitive action"})
            logger.warning("Blocking repetitive action '%s'", proposal.name)
            
            # Record as failed so AI sees it in history and tries something else
            Action.objects.create(
                attack_state=state,
                name=proposal.name,
                description=proposal.description,
                reasoning="System: Action blocked because it was recently executed successfully. Please choose a different action.",
                parameters=proposal.parameters,
                status='FAILED'
            )
            return True

        # 6. Policy Validation
        policy_decision = self.policy_engine.validate(
            proposal.name, state, proposal.parameters
        )
        self._log_audit(cycle_id, "POLICY_DECISION", {
            "allowed": policy_decision.allowed,
            "reason": policy_decision.reason
        })

        if not policy_decision.allowed:
            self._log_audit(cycle_id, "ACTION_BLOCKED", {"reason": policy_decision.reason})
            logger.warning(
                "Policy rejected action '%s': %s", proposal.name, policy_decision.reason
            )
            # TODO: Feed rejection back to AI memory (Phase 3)
            return False

        # 7. Queue Execution Task
        self._queue_execution(state, proposal, policy_decision, cycle_id)
        self.step_count += 1
        return True

    def _is_repetitive_action(self, state: AttackState, proposal) -> bool:
        """
        Check if this action was recently executed successfully with the same parameters.
        Helps prevent infinite loops if the AI keeps proposing the same valid action.
        """
        # Check last 5 completed actions
        recent = Action.objects.filter(
            attack_state=state,
            name=proposal.name,
            status='COMPLETED'
        ).order_by('-created_at')[:5]

        for action in recent:
            if action.parameters == proposal.parameters:
                return True
        return False

    def _has_pending_tasks(self) -> bool:
        """
        Check if there are pending execution tasks.

        Note: Since ExecutionTask currently lacks a direct link to AttackState,
        this checks for ANY pending task. In a multi-tenant system, this
        would need to be scoped to the specific attack simulation.
        """
        return ExecutionTask.objects.filter(
            status__in=['PENDING', 'RUNNING']
        ).exists()

    def _sync_action_states(self, state: AttackState) -> None:
        """
        Update Action records based on ExecutionTask results.
        This closes the loop between Executor and AI Memory.
        """
        pending_actions = Action.objects.filter(attack_state=state, status='PENDING')
        for action in pending_actions:
            # Find the task linked to this action
            # Note: parameters is a JSONField
            # FIX: Use direct foreign key instead of JSON lookup which fails on SQLite
            task = ExecutionTask.objects.filter(action=action).first()

            if task and task.status in ['COMPLETED', 'FAILED']:
                # Part B: Evaluate Result (Lightweight)
                if task.status == 'COMPLETED' and not task.output:
                    logger.warning("Task for action %s completed with empty output.", action.name)

                action.status = task.status
                action.save(update_fields=['status'])
                
                # Sync output to ActionResult (CORE-4)
                result, _ = ActionResult.objects.update_or_create(
                    action=action,
                    defaults={
                        "success": task.status == 'COMPLETED',
                        "output": task.output or {},
                        "log_message": task.error_message or f"Task {task.status}"
                    }
                )
                logger.debug("Synced Action %s status to %s", action.id, task.status)

                # Create Timeline Event for Dashboard Visibility (FB-1)
                AttackTimelineEvent.objects.create(
                    attack_state=state,
                    action=action,
                    event_type="EXECUTION",
                    phase=state.current_phase,
                    message=f"Executed {action.name}: {task.status}",
                    data={
                        "command": task.parameters.get('command', 'N/A'),
                        "output": task.output,
                        "error": task.error_message
                    }
                )

                if task.status == 'COMPLETED':
                    self._update_knowledge_base(state, action, task)
                    self._check_phase_progression(state, action)

    def _check_phase_progression(self, state: AttackState, action: Action) -> None:
        """
        Heuristic to automatically advance the attack phase based on successful actions.
        """
        # Map successful actions to the *next* logical phase
        transitions = {
            "PassiveRecon": "ENUMERATION",
            "HTTPHeaderFetch": "ENUMERATION",
            "EndpointDiscovery": "ENUMERATION",
            "ServiceEnumeration": "EXPLOITATION",
            "TechnologyFingerprint": "EXPLOITATION",
            "ExploitAttempt": "PRIVILEGE_ESCALATION",
            "PrivilegeEscalation": "PROOF_OF_COMPROMISE",
            "ProofOfCompromise": "COMPLETED"
        }

        next_phase = transitions.get(action.name)
        if not next_phase:
            return

        # Determine phase order indices
        phase_order = [p[0] for p in KILL_CHAIN_PHASES]
        
        try:
            current_idx = phase_order.index(state.current_phase)
            next_idx = phase_order.index(next_phase)

            # Only advance forward
            if next_idx > current_idx:
                old_phase = state.current_phase
                state.advance_phase(next_phase)
                
                logger.info("Auto-advancing phase: %s -> %s (Trigger: %s success)", 
                            old_phase, next_phase, action.name)
                
                AttackTimelineEvent.objects.create(
                    attack_state=state,
                    event_type="PHASE_TRANSITION",
                    phase=next_phase,
                    message=f"Phase auto-advanced to {next_phase} following successful {action.name}.",
                    action=action
                )
        except ValueError:
            logger.warning("Phase mismatch in progression check: %s or %s not in definitions.", state.current_phase, next_phase)

    def _update_knowledge_base(self, state: AttackState, action: Action, task: ExecutionTask) -> None:
        """
        Parses execution results and updates the persistent state_data.
        This enables the AI to 'remember' findings across steps.
        """
        if not state.state_data:
            state.state_data = {}
            
        # Ensure findings dict exists
        if 'findings' not in state.state_data:
            state.state_data['findings'] = {}
            
        # Extract text output safely
        text_output = ""
        if task.output:
            if isinstance(task.output, dict):
                # Prefer stdout if available, else dump whole dict
                text_output = task.output.get('stdout') or str(task.output)
            else:
                text_output = str(task.output)

        # 1. Parse Nmap / Service Enumeration
        if action.name == "ServiceEnumeration":
            # Simple regex to find open ports: "80/tcp open http"
            open_ports = re.findall(r'(\d+)/(tcp|udp)\s+open\s+([\w-]+)', text_output)
            
            if open_ports:
                target = action.parameters.get('target_host', 'unknown')
                services = []
                for port, proto, service in open_ports:
                    services.append({
                        "port": int(port),
                        "protocol": proto,
                        "service": service
                    })
                
                # Update enumeration section (used by DecisionEngine for known_services)
                if 'enumeration' not in state.state_data:
                    state.state_data['enumeration'] = {'services': {}}
                
                if 'services' not in state.state_data['enumeration']:
                    state.state_data['enumeration']['services'] = {}
                    
                state.state_data['enumeration']['services'][target] = services
                
                # Also add to findings for general context
                state.state_data['findings'][f"services_{target}"] = services
                logger.info("Parsed %d services for %s", len(services), target)

        # 2. Parse PassiveRecon (IP Resolution)
        elif action.name == "PassiveRecon":
            # Extract IPs from output (simple regex for IPv4)
            ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text_output)
            if ips:
                target = action.parameters.get('target_domain', 'unknown')
                unique_ips = list(set(ips))
                # Store resolved IPs specifically
                state.state_data['findings'][f"resolved_ips_{target}"] = unique_ips
                logger.info("Parsed IPs for %s: %s", target, unique_ips)

        # 3. Generic Output Storage (Catch-all)
        # Store the output of ANY successful action so the AI can reference it in the next step.
        # We use a key based on action name and target to make it retrievable.
        target = action.parameters.get('target_url') or action.parameters.get('target_host') or action.parameters.get('target_domain') or 'unknown'
        finding_key = f"{action.name}_{target}"
        
        # Store truncated output (limit to 1000 chars to save context window)
        state.state_data['findings'][finding_key] = text_output[:1000]

        state.save(update_fields=['state_data'])

    def _sync_defender_context(self, state: AttackState) -> None:
        """
        Inject defender alerts into the attack state so the AI can react (Re-plan).
        """
        alerts = DefenderAlert.objects.filter(attack_state=state)
        
        context = {
            "detected": alerts.exists(),
            "alert_count": alerts.count(),
            "max_severity": "NONE"
        }

        if alerts.exists():
            if alerts.filter(severity='CRITICAL').exists():
                context['max_severity'] = 'CRITICAL'
            elif alerts.filter(severity='HIGH').exists():
                context['max_severity'] = 'HIGH'
            elif alerts.filter(severity='MEDIUM').exists():
                context['max_severity'] = 'MEDIUM'
            else:
                context['max_severity'] = 'LOW'

        if not isinstance(state.state_data, dict):
            state.state_data = {}
            
        state.state_data['defender_context'] = context
        state.save(update_fields=['state_data'])

    def _sync_planner_context(self, state: AttackState) -> None:
        """
        Inject explicit goal and target context into state for the AI planner.
        This ensures the decision engine has a clear objective and target scope.
        """
        context = OperationalContextManager.get_active_context()
        if not context or not context.target:
            return

        target = context.target
        
        # Determine primary target reference (URL or IP)
        target_ref = target.base_url if target.base_url else target.ip_address
        
        planner_context = {
            "goal": "Perform reconnaissance to discover services and attempt exploitation of found vulnerabilities.",
            "targets": [{
                "name": target.name,
                "ip": target.ip_address,
                "url": target.base_url,
                "primary_ref": target_ref,
                "os": getattr(target, "operating_system", "Linux")
            }],
            "allowed_actions": ["PassiveRecon", "ServiceEnumeration", "ExploitAttempt", "PrivilegeEscalation", "ProofOfCompromise", "HTTPHeaderFetch", "TechnologyFingerprint", "EndpointDiscovery"],
            "instructions": ["Return at least ONE action if possible.", "Output must be valid JSON.", "Include a high-level plan with reasoning."]
        }
        
        if not isinstance(state.state_data, dict):
            state.state_data = {}
            
        state.state_data['planner_context'] = planner_context

        # Seed legacy fields for deterministic fallback
        # This ensures that if the AI fails, the deterministic engine has enough data to proceed.
        if not state.state_data.get('target_domain'):
            state.state_data['target_domain'] = target_ref
            
        if 'recon' not in state.state_data:
            state.state_data['recon'] = {}
        if 'domains' not in state.state_data['recon']:
            state.state_data['recon']['domains'] = [target_ref] if target_ref else []

        state.save(update_fields=['state_data'])

    def _sync_execution_history(self, state: AttackState) -> None:
        """
        Inject execution history into state_data so the AI can learn from results.
        """
        history = []
        # Fetch last 15 actions (most recent) to preserve context window
        recent_actions = Action.objects.filter(
            attack_state=state
        ).exclude(status='PENDING').order_by('-created_at')[:15]

        # Process in chronological order
        for action in reversed(list(recent_actions)):
            output_summary = "No output available"
            result = ActionResult.objects.filter(action=action).first()
            if result:
                if result.success:
                    # Truncate output to 800 chars to save tokens
                    raw = str(result.output)
                    output_summary = (raw[:800] + "...") if len(raw) > 800 else raw
                else:
                    output_summary = f"Failed: {result.log_message}"
            
            history.append({
                "action": action.name,
                "parameters": action.parameters,
                "status": action.status,
                "result": output_summary,
                "timestamp": action.created_at.isoformat()
            })

        if not isinstance(state.state_data, dict):
            state.state_data = {}
            
        state.state_data['execution_history'] = history
        state.save(update_fields=['state_data'])

    def _check_stop_conditions(self, state: AttackState) -> Optional[str]:
        """
        Check if the autonomous loop should stop.
        Returns the stop reason if it should stop, else None.
        """
        # OPS-9: Check Operational Context Liveness
        # Fail fast if executor disconnects or target becomes inactive
        context = OperationalContextManager.get_active_context()
        if not context:
            msg = "Operational Context lost (no active context)."
            logger.warning("STOP CONDITION: %s", msg)
            return msg

        is_valid, reason = OperationalContextManager.validate_readiness(context)
        if not is_valid:
            msg = f"Operational Context invalid: {reason}"
            logger.warning("STOP CONDITION: %s", msg)
            return msg

        # 1. Max Steps
        if self.step_count >= self.max_steps:
            msg = f"Max steps ({self.max_steps}) reached."
            logger.info("STOP CONDITION: %s", msg)
            return msg

        # 2. Defender Alerts
        # CRITICAL -> Halt immediately
        if DefenderAlert.objects.filter(
            attack_state=state,
            severity='CRITICAL'
        ).exists():
            msg = "Critical Defender Alert detected (HALT)."
            logger.warning("STOP CONDITION: %s", msg)
            return msg

        # HIGH -> Re-plan (Log and continue)
        if DefenderAlert.objects.filter(
            attack_state=state,
            severity='HIGH'
        ).exists():
            logger.info("Defender Alert (HIGH) detected. Triggering Re-plan (continuing loop).")
            # Do NOT return True. We want the AI to see the context and re-plan.

        # 3. Consecutive Failures
        # Check the last N actions
        recent_actions = Action.objects.filter(
            attack_state=state
        ).order_by('-created_at')[:self.max_consecutive_failures]

        if len(recent_actions) >= self.max_consecutive_failures:
            if all(a.status == 'FAILED' for a in recent_actions):
                msg = f"{self.max_consecutive_failures} consecutive failures detected."
                logger.warning("STOP CONDITION: %s", msg)
                return msg

        # 4. Plan Completion
        if self._is_plan_completed(state):
            msg = "Current plan completed."
            logger.info("STOP CONDITION: %s", msg)
            return msg

        return None

    def _log_audit(self, cycle_id: str, event: str, details: dict) -> None:
        """Write a structured audit log entry."""
        payload = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "cycle_id": cycle_id,
            "event": event,
            "attack_state_id": self.attack_state_id,
            "details": details
        }
        audit_logger.info(json.dumps(payload))

    def _queue_execution(self, state: AttackState, proposal, policy_decision, cycle_id: str) -> None:
        """
        Persist the decision as an Action and queue it for execution.
        """
        planned_command = ""
        for step in (state.current_plan or {}).get("steps", []):
            step_name = step.get("action_type") or step.get("action")
            if step_name == proposal.name and step.get("resolved_command"):
                planned_command = step.get("resolved_command") or ""
                break

        # Generate the shell command first to validate it
        generated = self.command_generator.generate(proposal.name, proposal.parameters)
        if planned_command:
            generated.shell_command = planned_command

        # Safety Check
        is_safe, safety_reason = self.safety_filter.validate(generated.shell_command)

        # TODO CORE-4: Temporary override for Web Mode tools (curl, whatweb)
        if not is_safe and any(tool in generated.shell_command for tool in ['curl', 'whatweb']):
            logger.info("Overriding safety filter for Web Mode tool: %s", generated.shell_command)
            is_safe = True

        # Resource Limits
        limits = self.safety_filter.get_resource_limits(proposal.name)

        with transaction.atomic():
            # 1. Create the Action record (for history/audit)
            # If unsafe, we mark it as FAILED immediately
            status = 'PENDING' if is_safe else 'FAILED'

            action = Action.objects.create(
                attack_state=state,
                name=proposal.name,
                description=proposal.description,
                reasoning=getattr(proposal, "reasoning", getattr(proposal, "rationale", "")),
                parameters=proposal.parameters,
                status=status
            )

            if not is_safe:
                logger.warning(
                    "Safety violation for action '%s': %s", proposal.name, safety_reason
                )
                self._log_audit(cycle_id, "SAFETY_VIOLATION", {
                    "action_id": action.id,
                    "command": generated.shell_command,
                    "reason": safety_reason
                })
                return

            # 2. Create the ExecutionTask (for the executor)
            # We inject the action_id so the executor can link the result back
            task_params = proposal.parameters.copy()
            task_params['_action_id'] = action.id
            task_params['_limits'] = limits
            task_params['command'] = generated.shell_command

            ExecutionTask.objects.create(
                action_name=proposal.name,
                action=action,
                parameters=task_params,
                status='PENDING',
                requires_approval=False,  # Future: Check policy_decision.requires_approval
            )

            logger.info(
                "Queued action '%s' (Action ID: %s) for execution.",
                proposal.name,
                action.id
            )

            self._log_audit(cycle_id, "EXECUTION_QUEUED", {
                "action_id": action.id,
                "action_name": proposal.name
            })

    def _is_plan_completed(self, state: AttackState) -> bool:
        """
        Check if all steps in the current plan have been successfully executed.
        """
        current_plan = state.current_plan
        if not current_plan or not isinstance(current_plan, dict):
            return False
            
        steps = current_plan.get('steps', [])
        if not steps:
            return False
            
        # Fetch completed actions
        completed_actions = list(Action.objects.filter(
            attack_state=state,
            status='COMPLETED'
        ).values('name', 'parameters'))
        
        # Try to match every step to a completed action
        for step in steps:
            step_name = step.get('action')
            step_params = step.get('parameters')
            if not isinstance(step_params, dict):
                step_params = {}
            
            matched_index = -1
            for i, action in enumerate(completed_actions):
                if action['name'] == step_name:
                    # Check parameters: step_params must be a subset of action['parameters']
                    action_params = action['parameters'] or {}
                    if all(action_params.get(k) == v for k, v in step_params.items()):
                        matched_index = i
                        break
            
            if matched_index != -1:
                completed_actions.pop(matched_index)
            else:
                return False
                
        return True
