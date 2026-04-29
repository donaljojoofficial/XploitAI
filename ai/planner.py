import json
import logging
import time
from copy import deepcopy
from dataclasses import replace
from typing import Dict, List, Optional, Tuple

from services.command_template_utils import (
    build_target_context,
    infer_required_tools,
    normalize_command_targets,
    normalize_command_template,
    render_command_template,
)
from ai.command_generator import CommandGenerator
from ai.llm.base import BaseLLMAdapter
from ai.llm.lmstudio_adapter import LMStudioAdapter
from ai.llm.nvidia_output_analysis_adapter import NvidiaOutputAnalysisAdapter
from ai.schemas import (
    ActionResultSummary,
    Decision,
    DecisionInput,
    KnownService,
    PastActionSummary,
    Plan,
    PlanStep,
)
from core.levels import (
    DEFAULT_LEVEL_LIMITS,
    DEFAULT_STEP_MAX_RETRIES,
    DEFAULT_STEP_RETRY_COOLDOWN_SECONDS,
    canonical_kill_chain_label,
    normalize_phase_name,
    pentest_stage_label,
    parse_positive_int,
)
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
        self._adapters_by_name = self._discover_adapters()
        self.adapter = self._get_adapter(provider)
        self.plan_adapter = self._get_plan_adapter(provider)
        self.review_adapter = self._get_review_adapter(provider)
        self.phase_review_adapter = NvidiaOutputAnalysisAdapter()
        self.last_plan_error: Optional[str] = None
        self._decision_cache: dict[str, dict] = {}
        self._decision_cache_ttl_seconds = 15.0

    def _get_adapter(self, provider: str) -> BaseLLMAdapter:
        requested_provider = (provider or "auto").lower()
        adapters_by_name = self._available_adapters()

        if requested_provider == "hybrid":
            if "groq" in adapters_by_name:
                return adapters_by_name["groq"]
            if "nvidia" in adapters_by_name:
                return adapters_by_name["nvidia"]
            return adapters_by_name["local"]

        if requested_provider == "local":
            from ai.llm.local_rule_engine import LocalRuleEngine
            return LocalRuleEngine()

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
        adapters_by_name = self._ai_only_adapters(self._available_adapters())

        if requested_provider == "local":
            return None

        if requested_provider == "hybrid":
            if not adapters_by_name:
                return None

            from ai.llm.task_router import TaskRouterAdapter
            hybrid_routes = {
                "plan": ["nvidia", "groq"],
                "plan.initial": ["nvidia", "groq"],
                "plan.reconnaissance": ["nvidia", "groq"],
                "plan.enumeration": ["nvidia", "groq"],
                "plan.exploitation": ["nvidia", "groq"],
                "plan.privilege_escalation": ["nvidia", "groq"],
                "plan.proof_of_compromise": ["nvidia", "groq"],
            }
            return TaskRouterAdapter(adapters_by_name, task_routes=hybrid_routes)

        if requested_provider not in {"auto", "fallback"}:
            return adapters_by_name.get(requested_provider)

        if not adapters_by_name:
            return None

        from ai.llm.task_router import TaskRouterAdapter
        return TaskRouterAdapter(adapters_by_name)

    def _get_review_adapter(self, provider: str) -> BaseLLMAdapter:
        requested_provider = (provider or "auto").lower()
        adapters_by_name = self._available_adapters()

        if requested_provider == "hybrid":
            return adapters_by_name.get("nvidia") or adapters_by_name["local"]

        return self.adapter

    def _available_adapters(self) -> Dict[str, BaseLLMAdapter]:
        return getattr(self, "_adapters_by_name", self._discover_adapters())

    def _requested_adapter_names(self, provider: Optional[str] = None) -> set[str]:
        requested_provider = (provider or self.provider or "auto").lower()
        if requested_provider in {"auto", "fallback"}:
            return {"gemini", "groq", "nvidia", "lmstudio"}
        if requested_provider == "hybrid":
            return {"nvidia", "groq"}
        if requested_provider == "local":
            return set()
        return {requested_provider}

    def _discover_adapters(self) -> Dict[str, BaseLLMAdapter]:
        adapters_by_name: Dict[str, BaseLLMAdapter] = {}
        requested_names = self._requested_adapter_names()

        if "gemini" in requested_names:
            try:
                from ai.llm.gemini import GeminiAdapter

                gemini = GeminiAdapter()
                if gemini._client:
                    adapters_by_name["gemini"] = gemini
            except Exception:
                pass

        if "groq" in requested_names:
            try:
                from ai.llm.groq_adapter import GroqAdapter

                groq = GroqAdapter()
                if groq._client:
                    adapters_by_name["groq"] = groq
            except Exception:
                pass

        if "nvidia" in requested_names:
            try:
                from ai.llm.nvidia_adapter import NvidiaAdapter

                nvidia = NvidiaAdapter()
                if nvidia._available:
                    adapters_by_name["nvidia"] = nvidia
            except Exception:
                pass

        if "lmstudio" in requested_names:
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

    def _ai_only_adapters(
        self,
        adapters_by_name: Dict[str, BaseLLMAdapter],
    ) -> Dict[str, BaseLLMAdapter]:
        return {
            name: adapter
            for name, adapter in (adapters_by_name or {}).items()
            if name != "local"
        }

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

        from core.models import AttackTarget, Command, ExecutionResult

        attack_state = state_manager.get_attack_state()
        current_state = state_manager.get_current_state_for_planner()
        phase = current_state.get("current_phase")

        phase_ready = self._ensure_active_phase_plan(state_manager, attack_state, phase)
        if not phase_ready:
            attack_state.current_phase = "COMPLETED"
            attack_state.save(update_fields=["current_phase"])
            logger.info("AIPlanner exhausted all phases for AttackState %s.", attack_state.id)
            return None

        attack_state.refresh_from_db()
        current_state = state_manager.get_current_state_for_planner()
        phase = current_state.get("current_phase")
        available_commands = list(state_manager.get_available_commands(phase))
        available_command_metadata = self._command_metadata(available_commands)

        next_step_hint = self._next_step_hint(attack_state)
        if attack_state.current_plan and not next_step_hint:
            phase_ready = self._advance_to_next_phase_with_plan(state_manager, attack_state)
            if not phase_ready:
                attack_state.current_phase = "COMPLETED"
                attack_state.save(update_fields=["current_phase"])
                logger.info("AIPlanner completed all phase plans for AttackState %s.", attack_state.id)
                return None

            attack_state.refresh_from_db()
            current_state = state_manager.get_current_state_for_planner()
            phase = current_state.get("current_phase")
            available_commands = list(state_manager.get_available_commands(phase))
            available_command_metadata = self._command_metadata(available_commands)
            next_step_hint = self._next_step_hint(attack_state)

        planned_command = None
        planned_command_name = None
        planned_phase = None
        if next_step_hint:
            planned_command, planned_command_name, planned_phase = self._resolve_planned_command(
                state_manager,
                attack_state,
                next_step_hint,
            )
            if planned_phase:
                available_commands = list(state_manager.get_available_commands(planned_phase))
                available_command_metadata = [
                    {
                        "id": c.id,
                        "name": c.name,
                        "description": c.description,
                    }
                    for c in available_commands
                ]

            if planned_command is None and not available_commands:
                logger.warning(
                    "AIPlanner could not resolve planned step '%s' to an executable command.",
                    next_step_hint.get("action_type") or next_step_hint.get("action"),
                )
                return None

            if planned_command is not None:
                prioritized_commands = [planned_command] + [
                    c for c in available_commands if c.id != planned_command.id
                ]
                available_commands = prioritized_commands
                available_command_metadata = [
                    {
                        "id": c.id,
                        "name": c.name,
                        "description": c.description,
                    }
                    for c in available_commands
                ]
        elif not available_commands:
            logger.info("No available commands for current phase. Falling back to deterministic engine.")
            return FallbackPlannerEngine(state_manager).get_next_command()

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
            chosen_name = None
            if planned_command_name and any(c.name == planned_command_name for c in available_commands):
                chosen_name = planned_command_name
            if not chosen_name:
                chosen_name = self._resolve_proposed_command_name(
                    proposal.action_type,
                    available_commands,
                )
            chosen = next((c for c in available_commands if c.name == chosen_name), None)
            if chosen:
                result = {
                    "command_id": chosen.id,
                    "command_name": chosen.name,
                    "reason": proposal.rationale or "Chosen by AI recommendation.",
                    "parameters": proposal.parameters or ((next_step_hint or {}).get("parameters") or {}),
                    "planned_command": (next_step_hint or {}).get("resolved_command") or "",
                    "required_tools": (next_step_hint or {}).get("resolved_tools") or [],
                }
                self._set_cached_decision(cache_key, result)
                return result
            else:
                logger.warning(f"LLM proposed unknown command: {proposal.action_type}")

        if planned_command is not None:
            result = {
                "command_id": planned_command.id,
                "command_name": planned_command.name,
                "reason": f"Following AI-generated plan step '{planned_command.name}'.",
                "parameters": (next_step_hint or {}).get("parameters") or {},
                "planned_command": (next_step_hint or {}).get("resolved_command") or "",
                "required_tools": (next_step_hint or {}).get("resolved_tools") or [],
            }
            self._set_cached_decision(cache_key, result)
            return result

        logger.info("Fallback planner engine engaged after LLM fallback.")
        return FallbackPlannerEngine(state_manager).get_next_command()

    def _command_metadata(self, commands) -> List[Dict[str, str]]:
        return [
            {
                "id": c.id,
                "name": c.name,
                "description": c.description,
                "phase": getattr(getattr(c, "phase", None), "name", None),
            }
            for c in (commands or [])
        ]

    def _render_step_command(
        self,
        attack_state,
        action_name: str,
        parameters: Optional[dict] = None,
    ) -> tuple[str, list[str], Optional[int]]:
        from core.models import Command

        parameters = parameters or {}
        available_commands = self._all_commands()
        resolved_name = self._resolve_proposed_command_name(action_name, available_commands)
        command_obj = next((c for c in available_commands if c.name == resolved_name), None)
        if not command_obj:
            return "", [], None

        target_context = build_target_context(
            (attack_state.state_data or {}).get("target")
            or (attack_state.state_data or {}).get("planner_context", {}).get("targets", [{}])[0].get("primary_ref", "")
        )
        render_context = {**target_context, **parameters}
        generator = CommandGenerator(use_llm=False, llm_provider="auto")
        try:
            command = generator.generate(command_obj.name, render_context).shell_command
            if not str(command or "").strip():
                command = render_command_template(
                    normalize_command_template(command_obj),
                    render_context,
                )
            command = normalize_command_targets(command, render_context)
        except KeyError:
            command = command_obj.command_template or ""
        return command, infer_required_tools(command), command_obj.id

    def _merged_attack_findings(self, attack_state) -> dict:
        state_data = attack_state.state_data if isinstance(attack_state.state_data, dict) else {}
        try:
            current_state = StateManager(attack_state.id).get_current_state_for_planner()
            merged = dict(current_state.get("findings") or {})
        except Exception:
            merged = dict(state_data.get("findings") or {})
        history = state_data.get("level_history") or state_data.get("phase_reviews") or []
        if isinstance(history, list):
            for item in history:
                if not isinstance(item, dict):
                    continue
                historical = item.get("findings")
                if isinstance(historical, dict):
                    for key, value in historical.items():
                        if key not in merged and value not in (None, "", [], {}):
                            merged[key] = deepcopy(value)
        return merged

    def _enrich_step_parameters(self, attack_state, action_name: str, parameters: Optional[dict] = None) -> dict:
        enriched = dict(parameters or {})
        findings = self._merged_attack_findings(attack_state)
        target_context = build_target_context(
            (attack_state.state_data or {}).get("target")
            or (attack_state.state_data or {}).get("planner_context", {}).get("targets", [{}])[0].get("primary_ref", "")
        )
        for key, value in target_context.items():
            if value not in (None, ""):
                enriched.setdefault(key, value)

        technologies = findings.get("identified_technologies") if isinstance(findings.get("identified_technologies"), list) else []
        if technologies:
            enriched.setdefault("tech", technologies[0])
            enriched.setdefault("product", technologies[0])

        endpoints = findings.get("discovered_endpoints") if isinstance(findings.get("discovered_endpoints"), list) else []
        if endpoints:
            enriched.setdefault("url", endpoints[0])
            enriched.setdefault("endpoint", endpoints[0])
            enriched.setdefault("target_url", enriched.get("target_url") or endpoints[0])
            first_path = str(endpoints[0]).split("/", 3)
            if len(first_path) >= 4:
                enriched.setdefault("login_path", "/" + first_path[3].split("?", 1)[0])

        parameters_found = findings.get("discovered_parameters") if isinstance(findings.get("discovered_parameters"), list) else []
        if parameters_found:
            enriched.setdefault("parameter_names", parameters_found)
            enriched.setdefault("candidate_parameter", parameters_found[0])

        creds = findings.get("valid_credentials") if isinstance(findings.get("valid_credentials"), list) else []
        if creds and isinstance(creds[0], dict):
            cred = creds[0]
            if cred.get("path"):
                enriched.setdefault("login_path", cred.get("path"))
            if cred.get("username"):
                enriched.setdefault("username", cred.get("username"))
            if cred.get("password"):
                enriched.setdefault("password", cred.get("password"))

        cookies = findings.get("session_cookies") if isinstance(findings.get("session_cookies"), list) else []
        if cookies:
            enriched.setdefault("session_cookie", cookies[0])

        proofs = findings.get("proof_of_compromise") if isinstance(findings.get("proof_of_compromise"), list) else []
        if proofs and isinstance(proofs[0], dict):
            enriched.setdefault("proof_path", proofs[0].get("path") or "")
            enriched.setdefault("loot_path", proofs[0].get("path") or "")

        if findings.get("proof_summary"):
            enriched.setdefault("evidence_tag", str(findings.get("proof_summary")))

        server_banner = findings.get("server_banner")
        if server_banner:
            enriched.setdefault("service", str(server_banner))

        action_token = (action_name or "").lower()
        if "fingerprint" in action_token and endpoints and enriched.get("url"):
            enriched["target_url"] = enriched.get("url")
        if "exploit" in action_token and parameters_found:
            enriched.setdefault("payload", f"{parameters_found[0]}=test")

        return enriched

    def _default_success_criteria(self, action_name: str) -> str:
        token = (action_name or "").strip().lower()
        if "proof" in token or "poc" in token:
            return "Collect explicit proof evidence linked to compromise."
        if "payload" in token:
            return "Generate and validate payload output with target-linked evidence."
        if "script" in token:
            return "Script executes without errors and returns expected exploit signal."
        if "exploit" in token:
            return "Obtain meaningful access or exploit evidence."
        if any(marker in token for marker in ("scan", "probe", "discover", "enumerat")):
            return "Discover actionable target surface evidence."
        return "Complete the step with meaningful evidence."

    def _step_execution_type(self, step: PlanStep) -> str:
        step_type = str(getattr(step, "execution_type", "") or "").strip().lower()
        if step_type in {"command", "script"}:
            return step_type
        action_name = str(getattr(step, "action_type", "") or "").strip().lower()
        if "script" in action_name or "payload" in action_name:
            return "script"
        return "command"

    def _default_script_content(self, action_name: str, parameters: Optional[dict] = None) -> str:
        params = parameters or {}
        target = (
            params.get("target")
            or params.get("target_url")
            or params.get("target_host")
            or "TARGET"
        )
        return (
            "# Auto-generated by XploitAI\n"
            "import urllib.request\n"
            "import urllib.parse\n\n"
            f"target = \"{str(target)}\".rstrip('/')\n"
            "payload = urllib.parse.urlencode({'username': \"' OR '1'='1\", 'password': 'test'}).encode()\n"
            "req = urllib.request.Request(target + '/login', data=payload)\n"
            "resp = urllib.request.urlopen(req, timeout=8)\n"
            "print('SCRIPT_STEP_ACTION: " + str(action_name) + "')\n"
            "print('SCRIPT_STATUS:', resp.status)\n"
            "print(resp.read(500).decode('utf-8', 'ignore'))\n"
        )

    def _serialize_plan_step(
        self,
        attack_state,
        step: PlanStep,
        runtime_profile: Optional[dict] = None,
        phase_name: Optional[str] = None,
    ) -> dict:
        runtime_profile = runtime_profile or {}
        step_max_retries = parse_positive_int(
            runtime_profile.get("max_retries", DEFAULT_STEP_MAX_RETRIES),
            DEFAULT_STEP_MAX_RETRIES,
        )
        step_retry_cooldown = parse_positive_int(
            runtime_profile.get("retry_cooldown_seconds", DEFAULT_STEP_RETRY_COOLDOWN_SECONDS),
            DEFAULT_STEP_RETRY_COOLDOWN_SECONDS,
        )
        enriched_parameters = self._enrich_step_parameters(attack_state, step.action_type, step.parameters)
        resolved_command, resolved_tools, command_id = self._render_step_command(
            attack_state,
            step.action_type,
            enriched_parameters,
        )
        normalized_phase = self._normalize_phase_name(phase_name or attack_state.current_phase)
        stage_label = (
            str(getattr(step, "stage_label", "") or "").strip().lower()
            or pentest_stage_label(normalized_phase)
        )
        execution_type = self._step_execution_type(step)
        script_language = getattr(step, "script_language", None) or ("python" if execution_type == "script" else None)
        script_content = getattr(step, "script_content", None) or None
        if execution_type == "script" and not script_content:
            script_content = self._default_script_content(step.action_type, step.parameters)

        artifact_refs = list(getattr(step, "artifact_refs", None) or [])
        enriched_parameters.setdefault("step_rationale", step.rationale)
        return {
            "step_number": step.step_number,
            "action_type": step.action_type,
            "parameters": enriched_parameters,
            "rationale": step.rationale,
            "stage_label": stage_label,
            "execution_type": execution_type,
            "script_language": script_language,
            "script_content": script_content,
            "artifact_refs": artifact_refs,
            "success_criteria": getattr(step, "success_criteria", None) or self._default_success_criteria(step.action_type),
            "resolved_command": resolved_command,
            "resolved_tools": resolved_tools,
            "command_id": command_id,
            "phase": normalized_phase,
            "status": "pending",
            "attempt_count": 0,
            "command_retry_count": 0,
            "max_retries": step_max_retries,
            "retry_cooldown_seconds": step_retry_cooldown,
            "next_allowed_at": 0,
            "alternative_pending": False,
            "execution_history": [],
        }

    def _ensure_active_phase_plan(
        self,
        state_manager: StateManager,
        attack_state,
        phase: str,
    ) -> bool:
        available_commands = list(state_manager.get_available_commands(phase))
        available_command_metadata = self._command_metadata(available_commands)

        if available_commands:
            return self._ensure_plan(
                attack_state,
                phase,
                available_command_metadata,
                force=self._plan_phase(attack_state.current_plan) != self._normalize_phase_name(phase),
            )

        return self._advance_to_next_phase_with_plan(state_manager, attack_state)

    def _advance_to_next_phase_with_plan(self, state_manager: StateManager, attack_state) -> bool:
        next_phase = self._advance_to_next_phase_with_commands(state_manager, attack_state)
        if not next_phase:
            return False

        available_commands = list(state_manager.get_available_commands(next_phase))
        return self._ensure_plan(
            attack_state,
            next_phase,
            self._command_metadata(available_commands),
            force=True,
        )

    def _advance_to_next_phase_with_commands(
        self,
        state_manager: StateManager,
        attack_state,
    ) -> Optional[str]:
        from core.models import Phase

        all_phases = list(Phase.objects.order_by("id").values_list("name", flat=True))
        current_lower = self._normalize_phase_name(attack_state.current_phase)
        try:
            current_idx = next(
                i for i, phase_name in enumerate(all_phases)
                if phase_name.lower() == current_lower
            )
        except StopIteration:
            current_idx = -1

        for next_phase_name in all_phases[current_idx + 1:]:
            if state_manager.get_available_commands(next_phase_name).exists():
                attack_state.current_phase = next_phase_name
                attack_state.current_plan = {}
                attack_state.save(update_fields=["current_phase", "current_plan"])
                logger.info(
                    "AIPlanner advancing from phase '%s' to '%s'.",
                    current_lower or attack_state.current_phase,
                    next_phase_name,
                )
                return next_phase_name

        return None

    def _normalize_phase_name(self, phase: Optional[str]) -> str:
        return normalize_phase_name(phase)

    def _phase_level_index(self, phase_name: str) -> int:
        from core.models import Phase

        normalized = self._normalize_phase_name(phase_name)
        ordered = list(Phase.objects.order_by("id").values_list("name", flat=True))
        for idx, current in enumerate(ordered, start=1):
            if self._normalize_phase_name(current) == normalized:
                return idx
        return 1

    def _level_metadata(self, phase_name: str) -> dict:
        normalized = self._normalize_phase_name(phase_name)
        return {
            "index": self._phase_level_index(normalized),
            "phase_name": normalized,
            "kill_chain_label": canonical_kill_chain_label(normalized),
            "status": "pending",
        }

    def _plan_phase(self, plan: Optional[dict]) -> str:
        if not isinstance(plan, dict):
            return ""
        return self._normalize_phase_name(plan.get("phase"))

    def _resolve_planned_command(
        self,
        state_manager: StateManager,
        attack_state,
        next_step_hint: dict,
    ) -> Tuple[Optional[object], Optional[str], Optional[str]]:
        from core.models import Command

        planned_name = next_step_hint.get("action_type") or next_step_hint.get("action")
        if not planned_name:
            return None, None, None

        completed_ids = ((attack_state.state_data or {}).get("completed_commands") or [])
        all_commands = list(Command.objects.select_related("phase"))
        resolved_name = self._resolve_proposed_command_name(planned_name, all_commands)
        if not resolved_name:
            return None, None, None

        resolved_command = next((c for c in all_commands if c.name == resolved_name), None)
        resolved_phase = getattr(getattr(resolved_command, "phase", None), "name", None)

        candidate_commands = [
            c for c in all_commands
            if c.id not in completed_ids
        ]

        chosen = next((c for c in candidate_commands if c.name == resolved_name), None)
        if resolved_phase and attack_state.current_phase != resolved_phase:
            attack_state.current_phase = resolved_phase
            attack_state.save(update_fields=["current_phase"])
            logger.info(
                "AIPlanner advancing phase to '%s' to execute planned step '%s'.",
                resolved_phase,
                resolved_name,
            )

        if chosen and getattr(chosen, "phase", None):
            chosen_phase = chosen.phase.name
            if chosen_phase and attack_state.current_phase != chosen_phase:
                attack_state.current_phase = chosen_phase
                attack_state.save(update_fields=["current_phase"])
                logger.info(
                    "AIPlanner advancing phase to '%s' to execute planned step '%s'.",
                    chosen_phase,
                    resolved_name,
                )
        return chosen, resolved_name, resolved_phase

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

    def _minimum_plan_steps(self, available_command_metadata: List[Dict[str, str]]) -> int:
        available_count = len(available_command_metadata or [])
        if available_count <= 0:
            return 1
        return min(available_count, 4)

    def _action_priority(self, action_name: str, phase: str) -> int:
        token = (action_name or "").strip().lower()
        phase_key = self._normalize_phase_name(phase)
        score = 0
        if any(k in token for k in ("exploit", "payload", "script", "shell", "poc")):
            score += 6
        if phase_key in {"exploitation", "post_exploitation", "proof_of_compromise"}:
            if any(k in token for k in ("payload", "script")):
                score += 6
            if "exploit" in token:
                score += 4
        if phase_key in {"reconnaissance", "discovery"} and any(k in token for k in ("header", "endpoint", "probe", "fingerprint")):
            score += 2
        return score

    def _prioritized_available_actions(
        self,
        available_command_metadata: List[Dict[str, str]],
        phase: str,
    ) -> List[Dict[str, str]]:
        ordered = list(available_command_metadata or [])
        ordered.sort(
            key=lambda item: (
                -self._action_priority(str(item.get("name") or ""), phase),
                str(item.get("name") or ""),
            )
        )
        return ordered

    def _supplement_plan_with_available_commands(
        self,
        plan: Optional[Plan],
        decision_input: DecisionInput,
        available_command_metadata: List[Dict[str, str]],
    ) -> Optional[Plan]:
        if not available_command_metadata:
            return plan

        minimum_steps = self._minimum_plan_steps(available_command_metadata)
        existing_steps = list((plan.steps if plan else []) or [])
        normalized_existing = {
            self._normalize_command_name(step.action_type)
            for step in existing_steps
            if getattr(step, "action_type", None)
        }

        supplemented_steps = list(existing_steps)
        prioritized_metadata = self._prioritized_available_actions(
            available_command_metadata,
            decision_input.phase,
        )
        for command_meta in prioritized_metadata:
            action_name = str(command_meta.get("name") or "").strip()
            if not action_name:
                continue
            normalized_name = self._normalize_command_name(action_name)
            if normalized_name in normalized_existing:
                continue

            supplemented_steps.append(
                PlanStep(
                    step_number=len(supplemented_steps) + 1,
                    action_type=action_name,
                    parameters={},
                    rationale=(
                        f"Supplemented to ensure {decision_input.phase} phase coverage for {action_name}."
                    ),
                )
            )
            normalized_existing.add(normalized_name)
            if len(supplemented_steps) >= minimum_steps:
                break

        phase_key = self._normalize_phase_name(decision_input.phase)
        if phase_key in {"exploitation", "post_exploitation", "proof_of_compromise"}:
            priority_markers = ("exploit", "payload", "script", "proof")
            available_by_name = {
                str(item.get("name") or "").strip(): item
                for item in prioritized_metadata
                if str(item.get("name") or "").strip()
            }
            wanted = [
                name for name in available_by_name.keys()
                if any(marker in name.lower() for marker in priority_markers)
            ]
            for name in wanted:
                normalized_name = self._normalize_command_name(name)
                if normalized_name in normalized_existing:
                    continue
                supplemented_steps.append(
                    PlanStep(
                        step_number=len(supplemented_steps) + 1,
                        action_type=name,
                        parameters={},
                        rationale=f"Deterministic exploit/payload supplementation for {phase_key}.",
                    )
                )
                normalized_existing.add(normalized_name)

        if not supplemented_steps:
            return None

        rationale = (plan.rationale if plan else None) or (
            f"Recovered phase plan for {decision_input.phase} from available commands."
        )
        return Plan(steps=supplemented_steps, rationale=rationale)

    def _dedupe_plan_steps(self, plan: Optional[Plan]) -> Optional[Plan]:
        if not plan or not plan.steps:
            return plan

        seen_actions: set[str] = set()
        deduped_steps: list[PlanStep] = []
        for step in plan.steps:
            action_name = getattr(step, "action_type", None)
            normalized = self._normalize_command_name(action_name or "")
            if not normalized:
                continue
            if normalized in seen_actions:
                logger.info("Dropping duplicate plan step for action '%s'.", action_name)
                continue
            seen_actions.add(normalized)
            deduped_steps.append(replace(step, step_number=len(deduped_steps) + 1))

        if not deduped_steps:
            return None
        return Plan(steps=deduped_steps, rationale=plan.rationale)

    def _recover_phase_plan(
        self,
        decision_input: DecisionInput,
        available_command_metadata: List[Dict[str, str]],
        plan: Optional[Plan],
    ) -> Optional[Plan]:
        recovered_plan = self._supplement_plan_with_available_commands(
            plan,
            decision_input,
            available_command_metadata,
        )
        minimum_steps = self._minimum_plan_steps(available_command_metadata)
        if recovered_plan and len(recovered_plan.steps) >= minimum_steps:
            return recovered_plan

        from ai.llm.local_rule_engine import LocalRuleEngine

        try:
            local_plan = LocalRuleEngine().get_plan(decision_input)
        except Exception as exc:
            logger.warning("Local phase plan recovery failed: %s", exc)
            local_plan = None

        recovered_plan = self._supplement_plan_with_available_commands(
            local_plan or recovered_plan,
            decision_input,
            available_command_metadata,
        )
        if recovered_plan and recovered_plan.steps:
            if local_plan and local_plan.steps:
                logger.info(
                    "AIPlanner recovered phase plan for '%s' using local fallback/supplementation.",
                    decision_input.phase,
                )
            return recovered_plan

        return None

    def _ensure_plan(
        self,
        attack_state,
        phase: str,
        available_command_metadata: List[Dict[str, str]],
        force: bool = False,
    ) -> bool:
        """Generate and persist a plan for the current active phase."""
        self.last_plan_error = None
        normalized_phase = self._normalize_phase_name(phase or attack_state.current_phase)
        if (
            not force
            and attack_state.current_plan
            and attack_state.current_plan.get("steps")
            and self._plan_phase(attack_state.current_plan) == normalized_phase
        ):
            return True
        if not self.plan_adapter:
            self.last_plan_error = "No AI planning adapter is available for plan generation."
            logger.warning("AIPlanner has no AI planning adapter available.")
            return False

        current_state = StateManager(attack_state.id).get_current_state_for_planner()
        known_services: List[KnownService] = []
        target = current_state.get("target") or (attack_state.state_data or {}).get("target")
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
            findings=current_state.get("findings", {}),
        )
        plan_task_key = self._plan_task_key(
            phase=phase or attack_state.current_phase,
            existing_plan=attack_state.current_plan,
        )

        plan = None
        try:
            plan = self.plan_adapter.get_plan(decision_input, task_key=plan_task_key)
        except Exception as e:
            self.last_plan_error = f"AI plan generation raised an exception: {e}"
            logger.warning(f"Plan generation failed in AIPlanner: {e}")
            return False

        minimum_steps = self._minimum_plan_steps(available_command_metadata)
        if not plan or not plan.steps:
            logger.warning(
                "AIPlanner received no usable phase plan for '%s'; attempting recovery.",
                phase or attack_state.current_phase,
            )
            plan = self._recover_phase_plan(
                decision_input,
                available_command_metadata,
                plan,
            )
            if not plan or not plan.steps:
                self.last_plan_error = "AI provider did not return a valid plan with steps."
                return False

        plan = self._dedupe_plan_steps(plan)
        if not plan or not plan.steps:
            self.last_plan_error = "AI provider returned only duplicate or invalid plan steps."
            return False

        if len(plan.steps) < minimum_steps:
            logger.warning(
                "AIPlanner received only %d step(s) for phase '%s'; supplementing to reach %d.",
                len(plan.steps),
                phase or attack_state.current_phase,
                minimum_steps,
            )
            plan = self._recover_phase_plan(
                decision_input,
                available_command_metadata,
                plan,
            )
            if not plan or len(plan.steps) < minimum_steps:
                self.last_plan_error = (
                    f"AI provider returned an incomplete plan with only {len((plan.steps if plan else []) or [])} steps; "
                    f"expected at least {minimum_steps} for this attack."
                )
                logger.warning(self.last_plan_error)
                return False
            plan = self._dedupe_plan_steps(plan)
            if not plan or not plan.steps:
                self.last_plan_error = "Recovered plan contained only duplicate or invalid steps."
                return False
            if len(plan.steps) < minimum_steps:
                self.last_plan_error = (
                    f"Recovered plan still has only {len(plan.steps)} unique step(s); "
                    f"expected at least {minimum_steps}."
                )
                logger.warning(self.last_plan_error)
                return False

        runtime_profile = (attack_state.state_data or {}).get("runtime_profile", {}) or {}
        runtime_limits = runtime_profile.get("limits") if isinstance(runtime_profile.get("limits"), dict) else {}
        level_limits = {
            key: parse_positive_int(runtime_limits.get(key, default_value), default_value)
            for key, default_value in DEFAULT_LEVEL_LIMITS.items()
        }

        attack_state.current_plan = {
            "phase": normalized_phase,
            "level": self._level_metadata(normalized_phase),
            "stage_label": pentest_stage_label(normalized_phase),
            "scope": "phase",
            "rationale": plan.rationale or "Plan generated by AIPlanner.",
            "limits": level_limits,
            "runtime": {
                "level_started_at": time.time(),
                "total_attempts": 0,
                "total_failures": 0,
                "paused_by_limits": False,
            },
            "steps": [self._serialize_plan_step(attack_state, s, runtime_profile, normalized_phase) for s in plan.steps],
        }
        if not isinstance(attack_state.state_data, dict):
            attack_state.state_data = {}
        attack_state.state_data["plan_approved"] = False
        attack_state.save(update_fields=["current_plan", "state_data"])
        logger.info(
            "AIPlanner generated phase plan for '%s' with %d step(s).",
            normalized_phase,
            len(plan.steps),
        )
        self.last_plan_error = None
        return True

    def ensure_initial_plan(self, state_manager: StateManager) -> bool:
        attack_state = state_manager.get_attack_state()
        current_state = state_manager.get_current_state_for_planner()
        phase = current_state.get("current_phase")
        available_commands = list(state_manager.get_available_commands(phase))
        return self._ensure_plan(
            attack_state,
            phase,
            self._command_metadata(available_commands),
            force=True,
        )

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

    def review_phase(
        self,
        state_manager: StateManager,
        phase_name: str,
    ) -> dict:
        from core.models import ExecutionResult

        attack_state = state_manager.get_attack_state()
        current_state = state_manager.get_current_state_for_planner()
        findings = current_state.get("findings", {}) or {}
        plan = (attack_state.current_plan or {}).copy()
        plan_steps = list(plan.get("steps") or [])
        phase_commands = [
            step.get("action_type") or step.get("action")
            for step in plan_steps
            if step.get("action_type") or step.get("action")
        ]
        recent_results = list(
            ExecutionResult.objects.filter(
                attack_state=attack_state,
                command__name__in=phase_commands,
            )
            .select_related("command")
            .order_by("-created_at")[:5]
        )

        latest_result_by_command = {}
        result_summaries = []
        for result in reversed(recent_results):
            command_name = getattr(result.command, "name", "unknown")
            latest_result_by_command[command_name] = result
            result_summaries.append(
                {
                    "command": command_name,
                    "status": result.status,
                    "stdout_excerpt": (result.stdout or "")[:400],
                    "stderr_excerpt": (result.stderr or "")[:240],
                    "findings": result.findings or {},
                }
            )

        command_reviews = []
        for step in plan_steps:
            command_name = step.get("action_type") or step.get("action") or "unknown"
            linked_result = latest_result_by_command.get(command_name)
            command_reviews.append(
                {
                    "command": command_name,
                    "purpose": step.get("rationale") or "",
                    "status": getattr(linked_result, "status", "PLANNED"),
                    "outcome": ((getattr(linked_result, "stdout", "") or getattr(linked_result, "stderr", ""))[:240] if linked_result else "Planned command for this phase."),
                    "resolved_command": step.get("resolved_command") or "",
                    "resolved_tools": step.get("resolved_tools") or [],
                }
            )

        phase_payload = {
            "phase": phase_name,
            "phase_plan_rationale": plan.get("rationale", ""),
            "commands_in_phase_plan": plan_steps,
            "completed_commands": phase_commands,
            "command_reviews": command_reviews,
            "recent_execution_results": result_summaries,
            "current_findings": findings,
        }
        prompt = (
            "You are writing a detailed phase review for a cyber-range operation.\n"
            "Use every concrete detail provided. Be factual and specific.\n"
            "Explain the phase objective, each command's purpose, what completed successfully, what failed, what evidence was gathered, and what should be checked before moving on.\n"
            "Return JSON only with this schema:\n"
            '{"summary":"...", "phase_objective":"...", "command_reviews":[{"command":"...", "purpose":"...", "status":"...", "outcome":"..."}], "key_evidence":["..."], "recommended_next_phase":"...", "operator_notes":"..."}\n'
            f"Phase data:\n{json.dumps(phase_payload, sort_keys=True, default=str)[:14000]}"
        )

        if self.phase_review_adapter:
            try:
                review = self.phase_review_adapter.analyze(prompt)
                if isinstance(review, dict):
                    review.setdefault("summary", "")
                    review.setdefault("phase_objective", "")
                    review.setdefault("command_reviews", command_reviews)
                    review.setdefault("key_evidence", [])
                    review.setdefault("recommended_next_phase", "")
                    review.setdefault("operator_notes", "")
                    review["phase"] = phase_name
                    review["plan_snapshot"] = plan_steps
                    review["results_snapshot"] = result_summaries
                    return review
            except Exception as exc:
                logger.warning("Phase review failed in AIPlanner: %s", exc)

        finding_keys = ", ".join(sorted(findings.keys())[:6]) or "no significant findings"
        return {
            "phase": phase_name,
            "summary": f"Completed phase {phase_name} with {finding_keys}.",
            "phase_objective": f"Review evidence gathered in {phase_name}.",
            "command_reviews": command_reviews,
            "key_evidence": sorted(findings.keys())[:6],
            "recommended_next_phase": self.peek_next_phase_with_commands(state_manager, attack_state) or "",
            "operator_notes": "Review the stored evidence before advancing.",
            "plan_snapshot": plan_steps,
            "results_snapshot": result_summaries,
        }

    def current_phase_completed(self, attack_state) -> bool:
        steps = (attack_state.current_plan or {}).get("steps") or []
        if not steps:
            return False
        explicit_statuses = [str(step.get("status") or "").lower() for step in steps]
        if any(status for status in explicit_statuses):
            return all(status == "completed" for status in explicit_statuses if status)
        return self._next_step_hint(attack_state) is None

    def peek_next_phase_with_commands(
        self,
        state_manager: StateManager,
        attack_state,
    ) -> Optional[str]:
        from core.models import Phase

        all_phases = list(Phase.objects.order_by("id").values_list("name", flat=True))
        current_lower = self._normalize_phase_name(attack_state.current_phase)
        try:
            current_idx = next(
                i for i, phase_name in enumerate(all_phases)
                if phase_name.lower() == current_lower
            )
        except StopIteration:
            current_idx = -1

        for next_phase_name in all_phases[current_idx + 1:]:
            if state_manager.get_available_commands(next_phase_name).exists():
                return next_phase_name

        return None

    def _next_step_hint(self, attack_state) -> Optional[dict]:
        """
        Return the first not-yet-successful plan step so recommendation stays
        incremental instead of generating the full command sequence at once.
        """
        steps = (attack_state.current_plan or {}).get("steps") or []
        if not steps:
            return None

        explicit_statuses = [str(step.get("status") or "").lower() for step in steps]
        if any(status for status in explicit_statuses):
            for step in steps:
                step_action = step.get("action_type") or step.get("action")
                step_status = str(step.get("status") or "").lower()
                if not step_action or step_status == "completed":
                    continue
                return {
                    "action_type": step_action,
                    "parameters": step.get("parameters", {}) or {},
                    "resolved_command": step.get("resolved_command") or "",
                    "resolved_tools": step.get("resolved_tools") or [],
                    "execution_type": step.get("execution_type") or "command",
                    "script_language": step.get("script_language"),
                    "script_content": step.get("script_content"),
                    "artifact_refs": step.get("artifact_refs") or [],
                    "success_criteria": step.get("success_criteria") or "",
                }
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
        failed_names = list(
            ExecutionResult.objects.filter(
                attack_state=attack_state,
                status="FAILED",
            )
            .exclude(command=None)
            .values_list("command__name", flat=True)
        )
        completed_ids = set(((attack_state.state_data or {}).get("completed_commands") or []))
        available_commands_by_name = {}
        for command in self._all_commands():
            available_commands_by_name.setdefault(command.name, []).append(command)

        remaining = list(succeeded_names)
        for step in steps:
            step_action = step.get("action_type") or step.get("action")
            if not step_action:
                continue
            if step_action in remaining:
                remaining.remove(step_action)
                continue
            if step_action in failed_names:
                unresolved_candidates = [
                    command for command in available_commands_by_name.get(step_action, [])
                    if command.id not in completed_ids
                ]
                if not unresolved_candidates:
                    logger.info(
                        "AIPlanner skipping exhausted failed plan step '%s' because no runnable commands remain for it.",
                        step_action,
                    )
                    continue
            return {
                "action_type": step_action,
                "parameters": step.get("parameters", {}) or {},
                "resolved_command": step.get("resolved_command") or "",
                "resolved_tools": step.get("resolved_tools") or [],
                "execution_type": step.get("execution_type") or "command",
                "script_language": step.get("script_language"),
                "script_content": step.get("script_content"),
                "artifact_refs": step.get("artifact_refs") or [],
                "success_criteria": step.get("success_criteria") or "",
            }

        return None

    def _all_commands(self):
        from core.models import Command

        return list(Command.objects.select_related("phase"))

