import logging
from typing import Dict, List, Optional

from ai.llm.base import BaseLLMAdapter
from ai.llm.lmstudio_adapter import LMStudioAdapter
from ai.schemas import ActionResultSummary, DecisionInput, KnownService, PastActionSummary
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
        self.adapter = self._get_adapter(provider)

    def _get_adapter(self, provider: str) -> BaseLLMAdapter:
        from core.config import get_config
        if provider == "auto":
            # Fallback to a default if not specified in settings
            provider = get_config("DEFAULT_LLM_PROVIDER", "fallback")

        # Try specific provider first to avoid initializing others unnecessarily
        if provider == "gemini":
            try:
                from ai.llm.gemini import GeminiAdapter
                gemini = GeminiAdapter()
                if gemini._client: return gemini
            except Exception: pass
        elif provider == "openai":
            try:
                from ai.llm.openai_adapter import OpenAIAdapter
                openai = OpenAIAdapter()
                if openai._available: return openai
            except Exception: pass
        elif provider == "groq":
            try:
                from ai.llm.groq_adapter import GroqAdapter
                groq = GroqAdapter()
                if groq._client: return groq
            except Exception: pass
        elif provider == "lmstudio":
            try:
                lmstudio = LMStudioAdapter()
                if lmstudio._available: return lmstudio
            except Exception: pass

        # Local provider has no external dependency
        if provider == "local":
            from ai.llm.local_rule_engine import LocalRuleEngine
            return LocalRuleEngine()

        # If specific provider failed or "fallback" was selected, initialize all available
        adapters = []
        
        try:
            from ai.llm.gemini import GeminiAdapter
            gemini = GeminiAdapter()
            if gemini._client: adapters.append(gemini)
        except Exception: pass
        
        try:
            from ai.llm.openai_adapter import OpenAIAdapter
            openai = OpenAIAdapter()
            if openai._available: adapters.append(openai)
        except Exception: pass

        try:
            from ai.llm.groq_adapter import GroqAdapter
            groq = GroqAdapter()
            if groq._client: adapters.append(groq)
        except Exception: pass
        
        try:
            lmstudio = LMStudioAdapter()
            if lmstudio._available: adapters.append(lmstudio)
        except Exception: pass

        from ai.llm.local_rule_engine import LocalRuleEngine
        adapters.append(LocalRuleEngine())

        from ai.llm.fallback import FallbackAdapter
        return FallbackAdapter(adapters)

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

        proposal = None
        try:
            proposal = self.adapter.get_recommendation(
                decision_input,
                next_step_hint=next_step_hint,
            )
        except Exception as e:
            logger.warning(f"LLM recommendation failed: {e}")

        if proposal is not None:
            chosen_name = proposal.action_type
            chosen = next((c for c in available_commands if c.name == chosen_name), None)
            if chosen:
                return {
                    "command_id": chosen.id,
                    "command_name": chosen.name,
                    "reason": proposal.rationale or "Chosen by AI recommendation.",
                }
            else:
                logger.warning(f"LLM proposed unknown command: {chosen_name}")

        logger.info("Fallback planner engine engaged after LLM fallback.")
        return FallbackPlannerEngine(state_manager).get_next_command()

    def _ensure_plan(
        self,
        attack_state,
        phase: str,
        available_command_metadata: List[Dict[str, str]],
    ) -> None:
        """Generate and persist an initial strategic plan once per attack run."""
        if attack_state.current_plan and attack_state.current_plan.get("steps"):
            return

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

        plan = None
        try:
            plan = self.adapter.get_plan(decision_input)
        except Exception as e:
            logger.warning(f"Plan generation failed in AIPlanner: {e}")
            return

        if not plan or not plan.steps:
            return

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

