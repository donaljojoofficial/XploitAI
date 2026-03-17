"""
Shared prompt construction logic for LLM adapters.
"""
import json
from ai.schemas import DecisionInput
from typing import List, Optional


def build_recommendation_prompt(decision_input: DecisionInput, allowed_actions: List[str] = None, next_step_hint: dict = None) -> str:
    phase = decision_input.phase or "unknown"
    phase_desc = "Tactical phase decisioning"

    service_name = "unknown"
    endpoint = "unknown"
    protocol = "unknown"
    if decision_input.known_services:
        svc = decision_input.known_services[0]
        service_name = svc.name
        endpoint = svc.endpoint or "unknown"
        protocol = svc.protocol or "unknown"

    if not decision_input.last_result:
        previous_line = "Previous command: none (first action)."
    else:
        success = "SUCCESS" if decision_input.last_result.success else "FAILED"
        error = decision_input.last_result.error or "none"
        output_text = decision_input.last_result.raw_output or decision_input.last_result.output_summary or ""
        previous_line = f"Previous command result: {success}\nError: {error}\nOutput:\n{output_text}"

    findings = decision_input.findings or {}
    findings_str = "Findings: none yet." if not findings else f"Findings:\n{json.dumps(findings, indent=2)}"

    history_items = []
    for a in (decision_input.past_actions or [])[-5:]:
        params = a.parameters or {}
        history_items.append(f"  {a.action_type}({params})")
    history_str = "History (recent):\n" + "\n".join(history_items) if history_items else "History (recent):\n  none"

    actions_text = ", ".join(allowed_actions) if allowed_actions else "all available actions"

    if next_step_hint:
        hint_action = next_step_hint.get("action_type") or next_step_hint.get("action")
        hint_params = next_step_hint.get("parameters") or {}
        task_line = (
            f"Execute planned step: action='{hint_action}', hint_parameters={hint_params}. "
            "Refine parameters from output. If impossible, pick closest alternative."
        )
    else:
        task_line = (
            f"Task: Choose the single best next action from: {actions_text}. "
            "Base your choice on the previous command output and findings. If FAILED, retry with corrected parameters or pick an alternative."
        )

    next_phase = phase
    if phase.upper() == "RECONNAISSANCE":
        next_phase = "ENUMERATION"
    elif phase.upper() == "ENUMERATION":
        next_phase = "EXPLOITATION"
    elif phase.upper() == "EXPLOITATION":
        next_phase = "PRIVILEGE_ESCALATION"
    elif phase.upper() == "PRIVILEGE_ESCALATION":
        next_phase = "PROOF_OF_COMPROMISE"

    prompt = (
        f"Phase: {phase} — {phase_desc}\n"
        f"Target: {service_name} ({protocol}://{endpoint})\n"
        f"{previous_line}\n"
        f"{findings_str}\n"
        f"{history_str}\n"
        f"{task_line}\n"
        f"Phase rule: stay in {phase} if there are still useful actions; suggest {next_phase} if phase objective is complete.\n"
        '{ "action_type": "...", "parameters": {}, "rationale": "one sentence: what was found and why this action", "suggested_next_phase": "{phase} or {next_phase}", "phase_reason": "one sentence: why this phase decision" }'
    )

    return prompt


def build_plan_prompt(decision_input: DecisionInput) -> str:
    phase = decision_input.phase or "unknown"
    phase_desc = "Tactical phase planning"
    service_name = "unknown"
    endpoint = "unknown"
    protocol = "unknown"
    if decision_input.known_services:
        svc = decision_input.known_services[0]
        service_name = svc.name
        endpoint = svc.endpoint or "unknown"
        protocol = svc.protocol or "unknown"

    if not decision_input.last_result:
        previous_line = "Previous command: none (first action)."
    else:
        success = "SUCCESS" if decision_input.last_result.success else "FAILED"
        error = decision_input.last_result.error or "none"
        output_text = decision_input.last_result.raw_output or decision_input.last_result.output_summary or ""
        previous_line = f"Previous command result: {success}\nError: {error}\nOutput:\n{output_text}"

    findings = decision_input.findings or {}
    findings_str = "Findings: none yet." if not findings else f"Findings:\n{json.dumps(findings, indent=2)}"

    already_done = "\n".join([f"  {a.action_type}({a.parameters})" for a in (decision_input.past_actions or [])]) or "None"

    phases_remaining = [
        "RECONNAISSANCE: gather initial data",
        "ENUMERATION: map discovered services",
        "EXPLOITATION: attempt controlled exploitation",
        "PRIVILEGE_ESCALATION: gain elevated access",
        "PROOF_OF_COMPROMISE: document success",
    ]

    allowed_actions = decision_input.available_commands or []
    allowed_list = "\n".join([f"  {item.get('name')}: {item.get('description', '')}" for item in allowed_actions]) or "  None"

    prompt = (
        f"Phase: {phase} — {phase_desc}\n"
        f"Target: {service_name} ({protocol}://{endpoint})\n"
        f"{previous_line}\n"
        f"{findings_str}\n"
        f"Already done actions:\n{already_done}\n"
        f"Phases remaining:\n{chr(10).join(phases_remaining)}\n"
        f"Allowed actions:\n{allowed_list}\n"
        '{ "steps": [ { "action_type": "...", "parameters": {}, "rationale": "..." } ] }'
    )

    return prompt


def build_narrative_prompt(decision_input: DecisionInput) -> str:
    phase = decision_input.phase or "unknown"
    phase_desc = "Tactical phase narration"
    service_name = "unknown"
    endpoint = "unknown"
    protocol = "unknown"
    if decision_input.known_services:
        svc = decision_input.known_services[0]
        service_name = svc.name
        endpoint = svc.endpoint or "unknown"
        protocol = svc.protocol or "unknown"

    if not decision_input.last_result:
        previous_line = "Previous command: none (first action)."
    else:
        success = "SUCCESS" if decision_input.last_result.success else "FAILED"
        error = decision_input.last_result.error or "none"
        output_text = decision_input.last_result.raw_output or decision_input.last_result.output_summary or ""
        previous_line = f"Previous command result: {success}\nError: {error}\nOutput:\n{output_text}"

    findings = decision_input.findings or {}
    findings_str = "Findings: none yet." if not findings else f"Findings:\n{json.dumps(findings, indent=2)}"

    next_phase = "unknown"
    if phase.upper() == "RECONNAISSANCE":
        next_phase = "ENUMERATION"
    elif phase.upper() == "ENUMERATION":
        next_phase = "EXPLOITATION"
    elif phase.upper() == "EXPLOITATION":
        next_phase = "PRIVILEGE_ESCALATION"
    elif phase.upper() == "PRIVILEGE_ESCALATION":
        next_phase = "PROOF_OF_COMPROMISE"
    elif phase.upper() == "PROOF_OF_COMPROMISE":
        next_phase = "COMPLETED"

    prompt = (
        f"Phase: {phase} — {phase_desc}\n"
        f"Target: {service_name} ({protocol}://{endpoint})\n"
        f"{previous_line}\n"
        f"{findings_str}\n"
        f"Task: Write 3-5 bullet Markdown status update. Cover: what ran, what was found, next step, whether to advance to {next_phase}. Reference actual output. No filler."
    )

    return prompt
