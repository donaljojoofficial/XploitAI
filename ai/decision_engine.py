import json
import logging
import re
from typing import Iterator, List, Optional
from core.models import AttackState, Action, AttackTarget, ActionResult
from ai.schemas import DecisionInput, DecisionRequest, KnownService, PastActionSummary, ActionResultSummary
from ai.schemas import DecisionInput, DecisionRequest, KnownService, PastActionSummary, ActionResultSummary, Plan, PlanStep

# Attempt to import GeminiAdapter
try:
    from ai.llm.gemini import GeminiAdapter
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False

logger = logging.getLogger(__name__)

class DecisionEngine:
    """
    AI Decision Engine responsible for generating attack actions.
    """
    
    def __init__(self):
        self.llm_adapter = None
        if LLM_AVAILABLE:
            try:
                self.llm_adapter = GeminiAdapter()
                logger.info("DecisionEngine initialized with GeminiAdapter.")
            except Exception as e:
                logger.error(f"Failed to initialize GeminiAdapter: {e}")

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
                # Truncate output to avoid context window overflow
                output_text = str(result.output) if result.output else "No output."
                if len(output_text) > 2000:
                    output_text = output_text[:2000] + "... (truncated)"
                
                last_result_summary = ActionResultSummary(
                    success=result.success,
                    output_summary=output_text,
                    error=result.log_message if not result.success else None
                )

        return DecisionInput(
            phase=state.current_phase,
            known_services=known_services,
            past_actions=past_actions,
            last_result=last_result_summary 
        )

    def generate_actions(self, attack_state: AttackState) -> list[Action]:
        """
        Generates a list of actions based on the current attack state.
        Includes a fallback mechanism to prevent autonomy stalls.
        """
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

        context = state.state_data.get('planner_context', {}).copy()
        
        # Inject the current plan into the context so the AI follows it
        if state.current_plan:
            context['active_plan'] = state.current_plan

        request = DecisionRequest(
            decision_input=decision_input,
            context=context
        )

        decision = self.llm_adapter.get_recommendation(request)
        
        if decision:
            return Action(
                attack_state=state,
                name=decision.action_type,
                description=decision.rationale or "AI generated action",
                reasoning=decision.rationale or "AI decision",
                parameters=decision.parameters,
                status="PENDING"
            )
        return None