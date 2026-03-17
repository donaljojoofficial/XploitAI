from __future__ import annotations

import json
import os
import logging
from typing import Iterator, Optional, Dict, Any, List

from ai.llm.base import BaseLLMAdapter
from ai.schemas import Decision, DecisionInput, Plan, PlanStep
from actions.predefined import _REGISTRY

logger = logging.getLogger(__name__)

# Load action graph once
ACTION_GRAPH_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "actions", "action_graph.json")
try:
    with open(os.path.abspath(ACTION_GRAPH_PATH), "r", encoding="utf-8") as f:
        ACTION_GRAPH = json.load(f)
except Exception:
    ACTION_GRAPH = {}

PHASE_KILL_CHAIN: Dict[str, List[str]] = {}
for action, meta in ACTION_GRAPH.items():
    phase = (meta.get("phase") or "").upper()
    if phase:
        PHASE_KILL_CHAIN.setdefault(phase, []).append(action)
        PHASE_KILL_CHAIN.setdefault(phase.lower(), []).append(action)

# support alternate names
PHASE_ORDER = ["RECONNAISSANCE", "ENUMERATION", "EXPLOITATION", "PRIVILEGE_ESCALATION", "PROOF_OF_COMPROMISE", "COMPLETED"]
PHASE_TRANSITION = {
    "RECONNAISSANCE": "ENUMERATION",
    "ENUMERATION": "EXPLOITATION",
    "EXPLOITATION": "PRIVILEGE_ESCALATION",
    "PRIVILEGE_ESCALATION": "PROOF_OF_COMPROMISE",
    "PROOF_OF_COMPROMISE": "COMPLETED",
}


def _collapse_known_service(decision_input: DecisionInput) -> Dict[str, str]:
    if not decision_input.known_services:
        return {}
    svc = decision_input.known_services[0]
    return {
        "name": svc.name,
        "endpoint": svc.endpoint or "",
        "protocol": svc.protocol or "",
    }


def _infer_parameters(action_type: str, decision_input: DecisionInput) -> Dict[str, Any]:
    params: Dict[str, Any] = {}
    svc = _collapse_known_service(decision_input)
    endpoint = svc.get("endpoint", "")

    # generic value source
    findings = decision_input.findings or {}

    if action_type == "PassiveRecon":
        if endpoint:
            params["target_domain"] = endpoint.split("//")[-1].split("/")[0]
        else:
            params["target_domain"] = "example.local"

    if action_type in ["HTTPHeaderFetch", "TechnologyFingerprint", "EndpointDiscovery"]:
        if endpoint:
            if endpoint.startswith("http"):
                params["target_url"] = endpoint
            else:
                params["target_url"] = f"http://{endpoint}"
        else:
            params["target_url"] = "http://localhost"

    if action_type in ["ServiceEnumeration", "ExploitAttempt", "PrivilegeEscalation"]:
        if endpoint:
            params["target_host"] = endpoint.split("//")[-1].split("/")[0]
        else:
            params["target_host"] = "localhost"

    if action_type == "ExploitAttempt":
        vuln = "CVE-XXXX-YYYY"
        if isinstance(findings, dict):
            maybe = findings.get("vulnerability") or findings.get("vulnerabilities")
            if isinstance(maybe, str) and maybe:
                vuln = maybe
            elif isinstance(maybe, list) and maybe:
                vuln = str(maybe[0])
        params["vulnerability_id"] = vuln

    if action_type == "ProofOfCompromise":
        params["evidence_tag"] = "proof-of-compromise"

    return params


def _get_score_and_reason(candidate: str, decision_input: DecisionInput) -> (int, str):
    score = 0
    reason_parts: List[str] = []

    past_actions = [a.action_type for a in (decision_input.past_actions or [])]
    attempts = past_actions.count(candidate)

    last_action = past_actions[-1] if past_actions else None
    if last_action and last_action in ACTION_GRAPH:
        successors = ACTION_GRAPH[last_action].get("next_actions", [])
        if candidate in successors:
            score += 3
            reason_parts.append("successor of last action")

    if candidate not in past_actions:
        score += 2
        reason_parts.append("not attempted yet")

    if decision_input.last_result and last_action == candidate:
        if decision_input.last_result.success:
            score += 1
            reason_parts.append("prior success")
        else:
            if attempts >= 3:
                score -= 5
                reason_parts.append("failed 3+ times")
            else:
                score -= 2
                reason_parts.append("failed once")
    elif attempts >= 3:
        score -= 5
        reason_parts.append("failed 3+ times")
    elif attempts > 0:
        score -= 2
        reason_parts.append("failed once")

    findings = decision_input.findings or {}
    if findings.get("recon", {}).get("http_headers") and candidate == "TechnologyFingerprint":
        score += 2
        reason_parts.append("http headers found")
    if findings.get("recon", {}).get("technologies") and candidate == "EndpointDiscovery":
        score += 2
        reason_parts.append("technologies found")
    if findings.get("enumeration", {}).get("endpoints") and candidate == "ExploitAttempt":
        score += 2
        reason_parts.append("endpoints found")
    if findings.get("exploitation", {}).get("compromised_hosts") and candidate == "PrivilegeEscalation":
        score += 2
        reason_parts.append("compromised hosts found")
    if findings.get("privilege_escalation") and candidate == "ProofOfCompromise":
        score += 2
        reason_parts.append("privilege escalation found")

    return score, ", ".join(reason_parts) if reason_parts else "default"


def _normalize_phase(phase: str) -> str:
    if not phase:
        return "RECONNAISSANCE"
    return phase.upper()


class LocalRuleEngine(BaseLLMAdapter):
    def _suggest_phase(
        self, action_type: str, decision_input: DecisionInput
    ) -> tuple:
        """
        Returns (suggested_next_phase, phase_reason).
        Advances phase when the chosen action is the last one needed
        in the current phase according to the kill-chain.
        """
        current_phase = (decision_input.phase or "RECONNAISSANCE").upper()
        completed = set(a.action_type for a in decision_input.past_actions) if decision_input.past_actions else set()
        chain = PHASE_KILL_CHAIN.get(current_phase, []) or PHASE_KILL_CHAIN.get(current_phase.lower(), [])

        # Actions still pending in this phase after this one runs
        remaining = [a for a in chain if a not in completed and a != action_type]

        PHASE_ORDER = [
            "RECONNAISSANCE", "ENUMERATION", "EXPLOITATION",
            "PRIVILEGE_ESCALATION", "PROOF_OF_COMPROMISE", "COMPLETED"
        ]
        try:
            idx = PHASE_ORDER.index(current_phase)
            next_phase = PHASE_ORDER[idx + 1] if idx + 1 < len(PHASE_ORDER) else "COMPLETED"
        except ValueError:
            next_phase = "ENUMERATION"

        if not remaining:
            return (
                next_phase,
                f"All {current_phase} actions complete after {action_type}; advancing to {next_phase}."
            )
        return (
            current_phase,
            f"{len(remaining)} action(s) still pending in {current_phase}."
        )

    def get_recommendation(self, decision_input: DecisionInput, next_step_hint: dict = None) -> Optional[Decision]:
        phase = _normalize_phase(decision_input.phase)

        if next_step_hint:
            hint_action = next_step_hint.get("action_type") or next_step_hint.get("action")
            if not hint_action:
                return None
            parameters = dict(next_step_hint.get("parameters") or {})
            inferred = _infer_parameters(hint_action, decision_input)
            for k, v in inferred.items():
                parameters.setdefault(k, v)
            selected = hint_action
            rationale = f"Executing next_step_hint action '{selected}'."

        else:
            candidates = PHASE_KILL_CHAIN.get(phase, []) or PHASE_KILL_CHAIN.get(phase.lower(), [])
            if not candidates:
                candidates = list(ACTION_GRAPH.keys())

            best_action = None
            best_score = -999
            best_reason = ""
            for candidate in candidates:
                score, reason = _get_score_and_reason(candidate, decision_input)
                if score > best_score:
                    best_score = score
                    best_action = candidate
                    best_reason = reason

            if not best_action:
                return None

            selected = best_action
            parameters = _infer_parameters(selected, decision_input)
            rationale = f"Selected '{selected}' by local rule scoring ({best_reason}, score={best_score})."

        suggested, reason = self._suggest_phase(selected, decision_input)
        return Decision(
            action_type=selected,
            parameters=parameters,
            rationale=rationale,
            suggested_next_phase=suggested,
            phase_reason=reason,
        )

    def get_plan(self, decision_input: DecisionInput) -> Optional[Plan]:
        phase = _normalize_phase(decision_input.phase)
        if phase not in PHASE_ORDER:
            phase = "RECONNAISSANCE"

        completed = set((a.action_type for a in (decision_input.past_actions or [])))
        steps: List[PlanStep] = []
        idx = PHASE_ORDER.index(phase) if phase in PHASE_ORDER else 0

        for phase_name in PHASE_ORDER[idx:]:
            if phase_name == "COMPLETED":
                break
            phase_actions = PHASE_KILL_CHAIN.get(phase_name, []) or PHASE_KILL_CHAIN.get(phase_name.lower(), [])
            if not phase_actions:
                continue

            selected = None
            for action in phase_actions:
                if action not in completed:
                    selected = action
                    break

            if not selected:
                continue

            params = _infer_parameters(selected, decision_input)
            steps.append(PlanStep(step_number=len(steps) + 1, action_type=selected, parameters=params, rationale=f"Local rule selected {selected} for phase {phase_name}."))
            completed.add(selected)

        if not steps:
            return None

        return Plan(steps=steps, rationale="Local rule engine generated plan.")

    def explain_decision(self, decision: Decision, decision_input: DecisionInput) -> Optional[str]:
        return f"LocalRuleEngine explains decision: selected {decision.action_type} with rationale: {decision.rationale}. Phase rule: {decision.phase_reason}."

    def generate(self, prompt: str) -> Optional[str]:
        return "LocalRuleEngine stub generation: prompt received."

    def generate_stream(self, prompt: str) -> Iterator[str]:
        text = "LocalRuleEngine stub generation stream."
        for word in text.split():
            yield word

    def get_attack_narrative(self, decision_input: DecisionInput) -> Iterator[str]:
        yield f"**Phase:** {decision_input.phase}"
        service = _collapse_known_service(decision_input)
        if service:
            yield f"**Target:** {service.get('name')} ({service.get('protocol', 'unknown')}://{service.get('endpoint')})"
        if decision_input.last_result:
            lr = decision_input.last_result
            status = "SUCCESS" if lr.success else "FAILED"
            yield f"**Last result:** {status} | Error: {lr.error or 'none'}"
        findings = decision_input.findings or {}
        yield f"**Findings:** {json.dumps(findings)}"

    def _parse_decision(self, text: str) -> Optional[Decision]:
        try:
            clean_text = text.replace("```json", "").replace("```", "").strip()
            start = clean_text.find("{")
            end = clean_text.rfind("}")
            if start != -1 and end != -1 and start < end:
                clean_text = clean_text[start : end + 1]
            data = json.loads(clean_text)
            return Decision(
                action_type=data.get("action_type", "wait"),
                parameters=data.get("parameters", {}),
                rationale=data.get("rationale"),
                suggested_next_phase=data.get("suggested_next_phase"),
                phase_reason=data.get("phase_reason"),
            )
        except Exception:
            return None
