import json
import logging
import time
from typing import Dict, List, Optional

from ai.llm.base import BaseLLMAdapter
from ai.llm.lmstudio_adapter import LMStudioAdapter
from ai.schemas import ActionResultSummary, Decision, DecisionInput, KnownService, PastActionSummary
from state.state_manager import StateManager

logger = logging.getLogger(__name__)


class FallbackPlannerEngine:
    """Deterministic engine used when no LLM provider is available."""

    PHASE_ORDER = [
        "RECONNAISSANCE",
        "ENUMERATION",
        "EXPLOITATION",
        "PRIVILEGE_ESCALATION",
        "PROOF_OF_COMPROMISE",
        "COMPLETED",
    ]

    def __init__(self, state_manager: StateManager):
        self.state_manager = state_manager

    def _get_next_phase(self, current_phase: str) -> str:
        current_phase = current_phase.upper() if current_phase else ""
        if current_phase not in self.PHASE_ORDER:
            return "RECONNAISSANCE"

        current_index = self.PHASE_ORDER.index(current_phase)
        if current_index + 1 < len(self.PHASE_ORDER):
            return self.PHASE_ORDER[current_index + 1]

        return "COMPLETED"

    def get_next_command(self) -> Optional[dict]:
        from core.models import AttackState, Phase

        current_state = self.state_manager.get_current_state_for_planner()
        phase = current_state.get("current_phase", "RECONNAISSANCE")

        # Try current phase first
        available_commands = list(self.state_manager.get_available_commands(phase))

        if not available_commands:
            # Current phase exhausted — advance through ALL remaining DB phases
            # until we find one with available commands.
            # Use actual DB phase order (by id) rather than hardcoded list,
            # so DB phase names ("discovery", "exploitation") are used correctly.
            attack_state = AttackState.objects.get(id=self.state_manager.attack_state_id)
            all_phases = list(Phase.objects.order_by("id").values_list("name", flat=True))

            current_lower = (attack_state.current_phase or "").lower()
            # Find position of current phase in DB order
            try:
                current_idx = next(
                    i for i, p in enumerate(all_phases)
                    if p.lower() == current_lower
                )
            except StopIteration:
                current_idx = -1

            # Walk forward through remaining phases
            for next_phase_name in all_phases[current_idx + 1:]:
                cmds = list(self.state_manager.get_available_commands(next_phase_name))
                if cmds:
                    attack_state.current_phase = next_phase_name
                    attack_state.save(update_fields=["current_phase"])
                    logger.info(
                        f"FallbackPlannerEngine: phase '{phase}' exhausted, "
                        f"advancing to '{next_phase_name}'."
                    )
                    available_commands = cmds
                    phase = next_phase_name
                    break

        if not available_commands:
            # Mark as COMPLETED if all phases exhausted
            attack_state = AttackState.objects.get(id=self.state_manager.attack_state_id)
            attack_state.current_phase = "COMPLETED"
            attack_state.save(update_fields=["current_phase"])
            logger.info("FallbackPlannerEngine: all phases exhausted. Marking COMPLETED.")
            return None

        chosen = available_commands[0]
        return {
            "command_id": chosen.id,
            "command_name": chosen.name,
            "reason": f"Fallback planner selects command '{chosen.name}' in phase '{phase}'.",
        }


class AIPlanner:
    """
    Uses an action graph and an LLM to decide the next best action.
    This is part of the new local execution architecture.
    """

    def __init__(self, provider: str = "auto"):
        self.provider = (provider or "auto").lower()
        self.adapter = self._get_adapter(provider)
        self.plan_adapter = self._get_plan_adapter(provider)
        self.review_adapter = self._get_review_adapter(provider)
        self._decision_cache: dict[str, dict] = {}
        self._decision_cache_ttl_seconds = 15.0

    def _get_adapter(self, provider: str) -> BaseLLMAdapter:
        requested_provider = (provider or "auto").lower()

        if requested_provider == "hybrid":
            adapters_by_name = self._discover_adapters()
            if "groq" in adapters_by_name:
                return adapters_by_name["groq"]
            if "nvidia" in adapters_by_name:
                return adapters_by_name["nvidia"]
            return adapters_by_name["local"]

        if requested_provider == "local":
            from ai.llm.local_rule_engine import LocalRuleEngine
            return LocalRuleEngine()

        adapters_by_name = self._discover_adapters()

        if requested_provider not in {"auto", "fallback"} and requested_provider in adapters_by_name:
            from ai.llm.task_router import TaskRouterAdapter
            return TaskRouterAdapter(
                adapters_by_name,
                task_routes=self._preferred_routes(requested_provider),
            )

        from ai.llm.task_router import TaskRouterAdapter
        return TaskRouterAdapter(adapters_by_name)

    def _get_plan_adapter(self, provider: str) -> BaseLLMAdapter:
        requested_provider = (provider or "auto").lower()
        adapters_by_name = self._discover_adapters()

        if requested_provider == "hybrid":
            return adapters_by_name.get("nvidia") or adapters_by_name.get("groq") or adapters_by_name["local"]

        return self.adapter

    def _get_review_adapter(self, provider: str) -> BaseLLMAdapter:
        requested_provider = (provider or "auto").lower()
        adapters_by_name = self._discover_adapters()

        if requested_provider == "hybrid":
            return adapters_by_name.get("nvidia") or adapters_by_name["local"]

        return self.adapter

    def _discover_adapters(self) -> Dict[str, BaseLLMAdapter]:
        adapters_by_name: Dict[str, BaseLLMAdapter] = {}

        try:
            from ai.llm.gemini import GeminiAdapter

            gemini = GeminiAdapter()
            if gemini._client:
                adapters_by_name["gemini"] = gemini
        except Exception:
            pass

        try:
            from ai.llm.groq_adapter import GroqAdapter

            groq = GroqAdapter()
            if groq._client:
                adapters_by_name["groq"] = groq
        except Exception:
            pass

        try:
            from ai.llm.nvidia_adapter import NvidiaAdapter

            nvidia = NvidiaAdapter()
            if nvidia._available:
                adapters_by_name["nvidia"] = nvidia
        except Exception:
            pass

        try:
            lmstudio = LMStudioAdapter()
            if lmstudio._available:
                adapters_by_name["lmstudio"] = lmstudio
        except Exception:
            pass

        from ai.llm.local_rule_engine import LocalRuleEngine

        adapters_by_name["local"] = LocalRuleEngine()
        return adapters_by_name

    def _preferred_routes(self, preferred_provider: str) -> Dict[str, List[str]]:
        from ai.llm.task_router import TaskRouterAdapter

        routes: Dict[str, List[str]] = {}
        for task_name, route in TaskRouterAdapter.DEFAULT_ROUTES.items():
            ordered = [name for name in route if name != preferred_provider]
            routes[task_name] = [preferred_provider] + ordered
        return routes

    def _normalize_phase_key(self, phase: Optional[str]) -> str:
        phase_name = (phase or "").strip().lower().replace(" ", "_")
        return phase_name or "reconnaissance"

    def _recommendation_task_key(self, decision_input: DecisionInput) -> str:
        if decision_input.last_result and not decision_input.last_result.success:
            return "recommendation.retry_failed_step"
        return f"recommendation.{self._normalize_phase_key(decision_input.phase)}"

    def _plan_task_key(self, phase: Optional[str], existing_plan: Optional[dict]) -> str:
        if not existing_plan or not existing_plan.get("steps"):
            return "plan.initial"
        return f"plan.{self._normalize_phase_key(phase)}"

    def _resolve_proposed_command_name(
        self,
        proposed_name: Optional[str],
        available_commands,
    ) -> Optional[str]:
        if not proposed_name:
            return None

        normalized_lookup = {
            self._normalize_command_name(command.name): command.name
            for command in available_commands
        }
        normalized_proposed = self._normalize_command_name(proposed_name)
        direct_match = normalized_lookup.get(normalized_proposed)
        if direct_match:
            return direct_match

        alias_map = {
            "passiverecon": ["HTTPHeaderFetch", "TechnologyFingerprint", "RobotsAndSitemap"],
            "serviceenumeration": ["EndpointDiscovery", "EndpointProbe", "ParameterDiscovery"],
            "servicediscovery": ["EndpointDiscovery", "EndpointProbe", "ParameterDiscovery"],
            "servicescan": ["EndpointDiscovery", "EndpointProbe", "ParameterDiscovery"],
            "vulnerabilityanalysis": ["VulnerabilityScanning", "SQLInjectionProbe"],
            "privilegeescalation": ["ProofOfCompromise"],
            "proofofcompromise": ["ProofOfCompromise"],
        }
        for alias_target in alias_map.get(normalized_proposed, []):
            resolved = normalized_lookup.get(self._normalize_command_name(alias_target))
            if resolved:
                return resolved

        for normalized_name, actual_name in normalized_lookup.items():
            if normalized_proposed in normalized_name or normalized_name in normalized_proposed:
                return actual_name

        return None

    def _normalize_command_name(self, command_name: str) -> str:
        return "".join(ch for ch in str(command_name).lower() if ch.isalnum())

    def get_next_command(self, state_manager: StateManager) -> Optional[dict]:
        """Determines the next command ID to execute one step at a time."""

        if not self.adapter:
            logger.info("No LLM provider active; using fallback planner engine.")
            return FallbackPlannerEngine(state_manager).get_next_command()

        from core.models import AttackTarget, Command, ExecutionResult

        current_state = state_manager.get_current_state_for_planner()
        phase = current_state.get("current_phase")

        available_commands = list(state_manager.get_available_commands(phase))
        if not available_commands:
            logger.info("No available commands for current phase. Falling back to deterministic engine.")
            return FallbackPlannerEngine(state_manager).get_next_command()

        available_command_metadata = [
            {"id": c.id, "name": c.name, "description": c.description}
            for c in available_commands
        ]

        attack_state = state_manager.get_attack_state()

        # Create plan once, then execute iteratively step-by-step from it.
        self._ensure_plan(attack_state, phase, available_command_metadata)
        next_step_hint = self._next_step_hint(attack_state)

        # Build a structured DecisionInput with last execution feedback so the
        # model can derive the next command from previous output.
        known_services: List[KnownService] = []
        target_ep = current_state.get("target")
        if target_ep:
            known_services.append(
                KnownService(
                    name="target",
                    endpoint=str(target_ep),
                    protocol="http" if "http" in str(target_ep) else "tcp",
                )
            )
        else:
            active_target = AttackTarget.objects.filter(is_active=True).first()
            if active_target:
                target_ep = active_target.base_url or active_target.ip_address
                if target_ep:
                    known_services.append(
                        KnownService(
                            name=active_target.name,
                            endpoint=target_ep,
                            protocol="http" if "http" in str(target_ep) else "tcp",
                        )
                    )

        completed_actions = current_state.get("completed_actions", []) or []
        if not completed_actions:
            completed_actions = list(
                ExecutionResult.objects.filter(
                    attack_state=attack_state,
                    status="SUCCESS",
                )
                .exclude(command=None)
                .values_list("command__name", flat=True)
            )

        past_actions = [
            PastActionSummary(action_type=str(action_name), parameters={})
            for action_name in completed_actions[-5:]
        ]

        last_exec = (
            ExecutionResult.objects.filter(attack_state=attack_state)
            .order_by("-created_at")
            .first()
        )
        last_result = None
        if last_exec:
            raw_output = (last_exec.stdout or "")[:1500]
            stderr = (last_exec.stderr or "").strip()
            output_summary = (last_exec.stdout or stderr or "")[:300]
            if output_summary and (len(last_exec.stdout or "") > 300):
                output_summary += "... (truncated)"

            last_result = ActionResultSummary(
                success=(last_exec.status == "SUCCESS"),
                output_summary=output_summary or "No output.",
                raw_output=raw_output or None,
                error=stderr or None,
            )

        decision_input = DecisionInput(
            phase=phase or attack_state.current_phase,
            known_services=known_services,
            past_actions=past_actions,
            available_commands=available_command_metadata,
            last_result=last_result,
            findings=current_state.get("findings"),
        )
        recommendation_task_key = self._recommendation_task_key(decision_input)

        cache_key = self._build_decision_cache_key(
            attack_state,
            decision_input,
            next_step_hint,
            available_command_metadata,
            completed_actions,
            last_exec,
        )
        cached = self._get_cached_decision(cache_key)
        if cached is not None:
            logger.info(
                "AIPlanner reusing cached recommendation for AttackState %s.",
                attack_state.id,
            )
            return cached

        proposal = None
        try:
            proposal = self.adapter.get_recommendation(
                decision_input,
                next_step_hint=next_step_hint,
                task_key=recommendation_task_key,
            )
        except Exception as e:
            logger.warning(f"LLM recommendation failed: {e}")

        if proposal is not None:
            chosen_name = self._resolve_proposed_command_name(
                proposal.action_type,
                available_commands,
            )
            if not chosen_name and next_step_hint:
                chosen_name = self._resolve_proposed_command_name(
                    next_step_hint.get("action_type") or next_step_hint.get("action"),
                    available_commands,
                )
            chosen = next((c for c in available_commands if c.name == chosen_name), None)
            if chosen:
                result = {
                    "command_id": chosen.id,
                    "command_name": chosen.name,
                    "reason": proposal.rationale or "Chosen by AI recommendation.",
                    "parameters": proposal.parameters or ((next_step_hint or {}).get("parameters") or {}),
                }
                self._set_cached_decision(cache_key, result)
                return result
            else:
                logger.warning(f"LLM proposed unknown command: {proposal.action_type}")

        logger.info("Fallback planner engine engaged after LLM fallback.")
        return FallbackPlannerEngine(state_manager).get_next_command()

    def _build_decision_cache_key(
        self,
        attack_state,
        decision_input: DecisionInput,
        next_step_hint: Optional[dict],
        available_command_metadata: List[Dict[str, str]],
        completed_actions: List[str],
        last_exec,
    ) -> str:
        payload = {
            "attack_state_id": attack_state.id,
            "phase": decision_input.phase,
            "known_services": [
                {
                    "name": svc.name,
                    "endpoint": svc.endpoint,
                    "protocol": svc.protocol,
                }
                for svc in (decision_input.known_services or [])
            ],
            "available_commands": available_command_metadata,
            "completed_actions": completed_actions,
            "next_step_hint": next_step_hint or {},
            "findings": decision_input.findings or {},
            "last_result": {
                "success": getattr(decision_input.last_result, "success", None),
                "output_summary": getattr(decision_input.last_result, "output_summary", None),
                "error": getattr(decision_input.last_result, "error", None),
            } if decision_input.last_result else None,
            "last_exec_id": getattr(last_exec, "id", None),
            "current_plan": attack_state.current_plan,
        }
        return json.dumps(payload, sort_keys=True, default=str)

    def _get_cached_decision(self, cache_key: str) -> Optional[dict]:
        entry = self._decision_cache.get(cache_key)
        if not entry:
            return None

        age = time.time() - entry["timestamp"]
        if age > self._decision_cache_ttl_seconds:
            self._decision_cache.pop(cache_key, None)
            return None

        return dict(entry["decision"])

    def _set_cached_decision(self, cache_key: str, decision: dict) -> None:
        self._decision_cache[cache_key] = {
            "timestamp": time.time(),
            "decision": dict(decision),
        }

    def _ensure_plan(
        self,
        attack_state,
        phase: str,
        available_command_metadata: List[Dict[str, str]],
    ) -> bool:
        """Generate and persist an initial strategic plan once per attack run."""
        if attack_state.current_plan and attack_state.current_plan.get("steps"):
            return True

        known_services: List[KnownService] = []
        target = (attack_state.state_data or {}).get("target")
        if target:
            known_services.append(
                KnownService(
                    name="target",
                    endpoint=str(target),
                    protocol="http" if "http" in str(target) else "tcp",
                )
            )

        decision_input = DecisionInput(
            phase=phase or attack_state.current_phase,
            known_services=known_services,
            past_actions=[],
            available_commands=available_command_metadata,
            findings=(attack_state.state_data or {}).get("findings", {}),
        )
        plan_task_key = self._plan_task_key(
            phase=phase or attack_state.current_phase,
            existing_plan=attack_state.current_plan,
        )

        plan = None
        try:
            plan = self.plan_adapter.get_plan(decision_input, task_key=plan_task_key)
        except Exception as e:
            logger.warning(f"Plan generation failed in AIPlanner: {e}")
            return False

        if not plan or not plan.steps:
            return False

        attack_state.current_plan = {
            "rationale": plan.rationale or "Plan generated by AIPlanner.",
            "steps": [
                {
                    "step_number": s.step_number,
                    "action_type": s.action_type,
                    "parameters": s.parameters,
                    "rationale": s.rationale,
                }
                for s in plan.steps
            ],
        }
        attack_state.save(update_fields=["current_plan"])
        logger.info(
            "AIPlanner generated initial plan with %d step(s).",
            len(plan.steps),
        )
        return True

    def ensure_initial_plan(self, state_manager: StateManager) -> bool:
        from core.models import Command, Phase

        attack_state = state_manager.get_attack_state()
        current_state = state_manager.get_current_state_for_planner()
        phase = current_state.get("current_phase")
        available_commands = list(state_manager.get_available_commands(phase))

        # For the initial strategy, expose commands across the remaining kill chain
        # so the reasoning model can build a full multi-phase plan instead of a
        # single-step local phase plan.
        phase_names = list(Phase.objects.order_by("id").values_list("name", flat=True))
        current_lower = (phase or attack_state.current_phase or "").lower()
        try:
            current_idx = next(i for i, name in enumerate(phase_names) if name.lower() == current_lower)
        except StopIteration:
            current_idx = 0

        remaining_phase_names = phase_names[current_idx:]
        if remaining_phase_names:
            available_commands = list(
                Command.objects.filter(phase__name__in=remaining_phase_names)
                .select_related("phase")
                .order_by("phase__id", "id")
            )

        available_command_metadata = [
            {
                "id": c.id,
                "name": c.name,
                "description": c.description,
                "phase": getattr(c.phase, "name", None),
            }
            for c in available_commands
        ]
        return self._ensure_plan(attack_state, phase, available_command_metadata)

    def review_execution(
        self,
        state_manager: StateManager,
        action_name: str,
        parameters: dict,
        success: bool,
        stdout: str,
        stderr: str,
    ) -> Optional[str]:
        if not self.review_adapter:
            return None

        current_state = state_manager.get_current_state_for_planner()
        known_services: List[KnownService] = []
        target = current_state.get("target")
        if target:
            known_services.append(
                KnownService(
                    name="target",
                    endpoint=str(target),
                    protocol="http" if "http" in str(target) else "tcp",
                )
            )

        decision_input = DecisionInput(
            phase=current_state.get("current_phase") or "RECONNAISSANCE",
            known_services=known_services,
            past_actions=[],
            findings=current_state.get("findings", {}),
            last_result=ActionResultSummary(
                success=success,
                output_summary=(stdout or stderr or "")[:300] or "No output.",
                raw_output=(stdout or stderr or "")[:1500] or None,
                error=stderr or None,
            ),
        )

        try:
            return self.review_adapter.explain_decision(
                Decision(
                    action_type=action_name,
                    parameters=parameters or {},
                    rationale=f"Execution {'succeeded' if success else 'failed'}.",
                ),
                decision_input,
            )
        except Exception as exc:
            logger.warning("Execution review failed in AIPlanner: %s", exc)
            return None

    def _next_step_hint(self, attack_state) -> Optional[dict]:
        """
        Return the first not-yet-successful plan step so recommendation stays
        incremental instead of generating the full command sequence at once.
        """
        steps = (attack_state.current_plan or {}).get("steps") or []
        if not steps:
            return None

        from core.models import ExecutionResult

        succeeded_names = list(
            ExecutionResult.objects.filter(
                attack_state=attack_state,
                status="SUCCESS",
            )
            .exclude(command=None)
            .values_list("command__name", flat=True)
        )

        remaining = list(succeeded_names)
        for step in steps:
            step_action = step.get("action_type") or step.get("action")
            if not step_action:
                continue
            if step_action in remaining:
                remaining.remove(step_action)
                continue
            return {
                "action_type": step_action,
                "parameters": step.get("parameters", {}) or {},
            }

        return None

