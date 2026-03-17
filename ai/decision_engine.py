import json
import logging
import os
import re
from typing import Iterator, List, Optional
from core.models import AttackState, Action, AttackTarget, ActionResult, Command
from ai.schemas import DecisionInput, DecisionRequest, KnownService, PastActionSummary, ActionResultSummary, Plan, PlanStep
from state.state_manager import StateManager

# Attempt to import Adapters
try:
    from ai.llm.gemini import GeminiAdapter
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

try:
    from ai.llm.anthropic import AnthropicAdapter
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    from ai.llm.groq_adapter import GroqAdapter
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False

try:
    from ai.llm.ollama_adapter import OllamaAdapter
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

from ai.llm.fallback import FallbackAdapter

logger = logging.getLogger(__name__)

class DecisionEngine:
    """
    AI Decision Engine responsible for generating attack actions.
    """
    
    def __init__(self, provider: str = "auto"):
        self.llm_adapter = None
        
        adapters = []
        
        if provider == "auto":
            from core.config import get_config
            provider = get_config("DEFAULT_LLM_PROVIDER", "fallback")

        # Local provider has no external dependency
        if provider == "local":
            from ai.llm.local_rule_engine import LocalRuleEngine
            self.llm_adapter = LocalRuleEngine()
            logger.info("DecisionEngine initialized with LocalRuleEngine.")
            return
            
        def _init_gemini():
            if GEMINI_AVAILABLE:
                # Check for API keys to avoid potential crashes in adapter initialization
                google_key = os.getenv("GOOGLE_API_KEY")
                gemini_key = os.getenv("GEMINI_API_KEY")

                if not google_key and not gemini_key:
                    logger.warning("Skipping GeminiAdapter: Missing GOOGLE_API_KEY or GEMINI_API_KEY.")
                    return None

                if not google_key and gemini_key:
                    os.environ["GOOGLE_API_KEY"] = gemini_key

                try:
                    gemini = GeminiAdapter()
                    if gemini._client:
                        return gemini
                except Exception as e:
                    logger.error(f"Failed to initialize GeminiAdapter: {e}")
            return None

        def _init_anthropic():
            if ANTHROPIC_AVAILABLE:
                try:
                    anthropic = AnthropicAdapter()
                    if anthropic._client or anthropic._use_raw_http:
                        return anthropic
                except Exception as e:
                    logger.error(f"Failed to initialize AnthropicAdapter: {e}")
            return None

        def _init_groq():
            if GROQ_AVAILABLE:
                try:
                    groq = GroqAdapter()
                    if groq._client:
                        return groq
                except Exception as e:
                    logger.error(f"Failed to initialize GroqAdapter: {e}")
            return None

        def _init_ollama():
            if OLLAMA_AVAILABLE:
                try:
                    ollama_inst = OllamaAdapter()
                    if ollama_inst._client:
                        return ollama_inst
                except Exception as e:
                    logger.error(f"Failed to initialize OllamaAdapter: {e}")
            return None

        if provider == "gemini":
            adapter = _init_gemini()
            if adapter:
                adapters.append(adapter)
        elif provider == "claude":
            adapter = _init_anthropic()
            if adapter:
                adapters.append(adapter)
        elif provider == "groq":
            adapter = _init_groq()
            if adapter:
                adapters.append(adapter)
        elif provider == "ollama":
            adapter = _init_ollama()
            if adapter:
                adapters.append(adapter)
        else:
            # Auto / Fallback mode
            g = _init_gemini()
            if g: adapters.append(g)
            a = _init_anthropic()
            if a: adapters.append(a)
            gr = _init_groq()
            if gr: adapters.append(gr)
            ol = _init_ollama()
            if ol: adapters.append(ol)

        from ai.llm.local_rule_engine import LocalRuleEngine
        adapters.append(LocalRuleEngine())

        if len(adapters) > 1:
            self.llm_adapter = FallbackAdapter(adapters)
            logger.info(f"DecisionEngine initialized with FallbackAdapter ({len(adapters)} providers).")
        elif len(adapters) == 1:
            self.llm_adapter = adapters[0]
            logger.info(f"DecisionEngine initialized with {adapters[0].__class__.__name__}.")

    def generate_attack_narrative(self, decision_input: DecisionInput) -> Iterator[str]:
        """
        Generates a streaming narrative of the current attack state.
        
        Args:
            decision_input: The current state of the attack.
            
        Returns:
            An iterator yielding chunks of the narrative text.
        """
        if not self.llm_adapter:
            # Fallback or empty iterator if LLM is disabled
            return iter([])
            
        return self.llm_adapter.get_attack_narrative(decision_input)
    def _build_decision_input(self, state: AttackState) -> DecisionInput:
        """Helper to build DecisionInput from AttackState."""
        known_services = []
        
        # Seed with active target if no services known yet (ensures LLM has target context)
        if not known_services:
            active_target = AttackTarget.objects.filter(is_active=True).first()
            if active_target:
                target_ep = active_target.base_url or active_target.ip_address
                if target_ep:
                    known_services.append(KnownService(
                        name=active_target.name,
                        endpoint=target_ep,
                        protocol="http" if "http" in target_ep else "tcp"
                    ))

        if state.state_data and 'enumeration' in state.state_data:
            services = state.state_data['enumeration'].get('services', {})
            for host, svc_list in services.items():
                for svc in svc_list:
                    known_services.append(KnownService(
                        name=svc.get('service', 'unknown'),
                        endpoint=f"{host}:{svc.get('port')}",
                        protocol=svc.get('service')
                    ))

        past_actions = []
        # Use the last 5 actions for context
        recent_actions = state.actions.order_by('-created_at')[:5]
        for a in recent_actions:
            past_actions.append(PastActionSummary(
                action_type=a.name,
                parameters=a.parameters,
                phase=state.current_phase,
                timestamp=str(a.created_at)
            ))

        # Retrieve the result of the last finished action to provide feedback
        last_result_summary = None
        last_finished_action = state.actions.exclude(status='PENDING').order_by('-created_at').first()
        
        if last_finished_action:
            result = ActionResult.objects.filter(action=last_finished_action).first()
            if result:
                raw_output = None
                if isinstance(result.output, dict):
                    raw_output = result.output.get("stdout") or result.output.get("output")
                if not raw_output:
                    raw_output = str(result.output) if result.output else ""
                raw_output = raw_output[:1500]

                output_summary = str(result.output) if result.output else "No output."
                if len(output_summary) > 2000:
                    output_summary = output_summary[:2000] + "... (truncated)"

                last_result_summary = ActionResultSummary(
                    success=result.success,
                    output_summary=output_summary,
                    raw_output=raw_output,
                    error=result.log_message if not result.success else None
                )

        findings = state.state_data.get('findings', {}) if state.state_data else {}

        return DecisionInput(
            phase=state.current_phase,
            known_services=known_services,
            past_actions=past_actions,
            last_result=last_result_summary,
            findings=findings
        )

    def generate_actions(self, attack_state: AttackState) -> list[Action]:
        """
        Generates a list of actions based on the current attack state.
        Includes a fallback mechanism to prevent autonomy stalls.
        """
        # If no LLM adapter is available, use the deterministic fallback planner engine.
        if not self.llm_adapter:
            from ai.planner import FallbackPlannerEngine
            logger.info("No LLM adapter available in DecisionEngine; using FallbackPlannerEngine.")
            fallback = FallbackPlannerEngine(StateManager(attack_state.id))
            plan = fallback.get_next_command()
            if not plan:
                return []

            action = Action(
                attack_state=attack_state,
                name=Command.objects.get(id=plan['command_id']).name if plan.get('command_id') else 'Unknown',
                description=plan.get('reason', 'Fallback planner selected command'),
                reasoning=plan.get('reason', 'Fallback planner selected command'),
                parameters={"target_url": attack_state.state_data.get('target')} if attack_state.state_data else {},
                status='PENDING'
            )
            return [action]

        proposed_actions = []
        
        # 1. AI Planning Logic
        if self.llm_adapter:
            try:
                # Check if we need to generate or update the plan
                # Condition: No plan exists OR last action failed (re-plan)
                should_plan = not attack_state.current_plan
                
                if not should_plan:
                    last_action = attack_state.actions.exclude(status='PENDING').order_by('-created_at').first()
                    if last_action and last_action.status == 'FAILED':
                        should_plan = True
                        logger.info("Last action failed. Triggering re-planning.")

                if should_plan:
                    plan = self.generate_plan(attack_state)
                    
                    if plan:
                        # Mark plan as unapproved
                        if not attack_state.state_data:
                            attack_state.state_data = {}
                        attack_state.state_data['plan_approved'] = False
                        attack_state.save(update_fields=['state_data'])
                        logger.info("Plan generated. Stopping for user approval.")
                        return []

                    # Enforce strict planning: If planning fails and we have no plan, do not proceed.
                    if not plan and not attack_state.current_plan:
                        logger.warning("Plan generation failed. Aborting AI proposal to enforce planning first.")
                        # Raise exception to break out of AI block and trigger fallback logic
                        raise ValueError("Planning failed, skipping AI proposal")

                # Check if plan is approved
                if attack_state.current_plan and not (attack_state.state_data or {}).get('plan_approved', False):
                    logger.info("Plan exists but not approved. Waiting.")
                    return []

                ai_action = self._get_ai_proposal(attack_state)
                if ai_action:
                    logger.info(f"AI proposed action: {ai_action.name}")
                    proposed_actions.append(ai_action)
            except Exception as e:
                logger.error(f"Error getting AI proposal: {e}")
        
        # --- FALLBACK LOGIC (TODO CORE-1) ---
        # If no actions were generated by the AI, and we have active targets,
        # generate a fallback reconnaissance action to prevent autonomy stall.
        if not proposed_actions:
            # Check if we are waiting for approval - if so, do NOT run fallback
            if attack_state.current_plan and not (attack_state.state_data or {}).get('plan_approved', False):
                return []

            # 1. Identify Target (Prefer Context, then DB)
            target_url = None
            if attack_state.state_data and 'planner_context' in attack_state.state_data:
                targets = attack_state.state_data['planner_context'].get('targets', [])
                if targets:
                    target_url = targets[0].get('url') or targets[0].get('primary_ref')
            
            if not target_url:
                active_targets = AttackTarget.objects.filter(is_active=True)
                if active_targets.exists():
                    target = active_targets.first()
                    target_url = target.base_url
                    if not target_url and target.ip_address:
                        target_url = f"http://{target.ip_address}"
            
            if target_url:
                # 2. Determine Next Action based on History (Web Kill Chain)
                executed_actions = set(
                    attack_state.actions.filter(status='COMPLETED').values_list('name', flat=True)
                )
                
                next_action_name = None
                if "HTTPHeaderFetch" not in executed_actions:
                    next_action_name = "HTTPHeaderFetch"
                elif "TechnologyFingerprint" not in executed_actions:
                    next_action_name = "TechnologyFingerprint"
                elif "EndpointDiscovery" not in executed_actions:
                    next_action_name = "EndpointDiscovery"
                
                if next_action_name:
                    logger.info(f"DecisionEngine: Proposing {next_action_name} for {target_url}")
                    fallback_action = Action(
                        attack_state=attack_state,
                        name=next_action_name,
                        description=f"Automated web attack step: {next_action_name}",
                        reasoning="Following web kill chain sequence.",
                        parameters={"target_url": target_url},
                        status="PENDING"
                    )
                    proposed_actions.append(fallback_action)
                    
        return proposed_actions

    def generate_plan(self, attack_state: AttackState) -> Optional[Plan]:
        """
        Generates a full attack plan based on the current state using the LLM.
        """
        if not self.llm_adapter:
            logger.warning("LLM adapter not available for planning.")
            return None
        
        try:
            decision_input = self._build_decision_input(attack_state)
            plan = self.llm_adapter.get_plan(decision_input)
            
            if plan:
                # Save plan to AttackState
                attack_state.current_plan = {
                    "rationale": plan.rationale,
                    "steps": [
                        {
                            "step": s.step_number,
                            "action": s.action_type,
                            "parameters": s.parameters,
                            "rationale": s.rationale
                        }
                        for s in plan.steps
                    ]
                }
                attack_state.save(update_fields=['current_plan'])
                logger.info("Generated and saved new attack plan.")
                
            return plan
            
        except Exception as e:
            logger.error(f"Error generating plan: {e}")
            return None

    def _get_ai_proposal(self, state: AttackState) -> Optional[Action]:
        """
        Helper to get a proposal from the LLM adapter.
        """
        decision_input = self._build_decision_input(state)

        # FIX BUG-AI-1: Identify next plan step to guide the AI
        next_step_hint = None
        if state.current_plan and 'steps' in state.current_plan:
            # Get completed actions to match against plan
            completed_actions = list(state.actions.filter(status='COMPLETED').values('name', 'parameters'))
            
            for step in state.current_plan['steps']:
                step_action = step.get('action')
                step_params = step.get('parameters', {}) or {}
                
                # Check if step is completed
                matched = False
                for i, ca in enumerate(completed_actions):
                    if ca['name'] == step_action:
                        # Relaxed Matching:
                        # We match by Action Name primarily. We do NOT enforce strict parameter matching
                        # because the AI might have refined the parameters (e.g. domain -> IP) based on findings.
                        # Since we process steps in order, consuming the first matching completed action is safe.
                        matched = True
                        completed_actions.pop(i) # Consume action so it doesn't match twice
                        break
                
                if not matched:
                    next_step_hint = step
                    break

        # Pass next_step_hint to the adapter (Adapters must be updated to accept this argument)
        decision = self.llm_adapter.get_recommendation(decision_input, next_step_hint=next_step_hint)
        
        if decision:
            action = Action(
                attack_state=state,
                name=decision.action_type,
                description=decision.rationale or "AI generated action",
                reasoning=decision.rationale or "AI decision",
                parameters=decision.parameters,
                status="PENDING"
            )

            # NEW: store phase suggestion in action reasoning so it surfaces
            # in the dashboard, and apply phase transition if suggested.
            if decision.suggested_next_phase:
                next_p = decision.suggested_next_phase.upper()
                current_p = state.current_phase.upper()
                phase_note = f" | Phase: {decision.phase_reason or 'advance suggested'}"
                action.reasoning = (action.reasoning or "") + phase_note

                # Only advance — never go backwards
                PHASE_ORDER = [
                    "RECONNAISSANCE", "ENUMERATION", "EXPLOITATION",
                    "PRIVILEGE_ESCALATION", "PROOF_OF_COMPROMISE", "COMPLETED"
                ]
                if (next_p in PHASE_ORDER and current_p in PHASE_ORDER
                        and PHASE_ORDER.index(next_p) > PHASE_ORDER.index(current_p)):
                    state.current_phase = next_p
                    state.save(update_fields=["current_phase"])
                    logger.info(
                        f"DecisionEngine: phase advanced {current_p} → {next_p}. "
                        f"Reason: {decision.phase_reason}"
                    )

            return action
        return None