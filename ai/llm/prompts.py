"""
Shared prompt construction logic for LLM adapters.
"""
import json
from typing import List

from ai.schemas import DecisionInput

PHASE_DESCRIPTIONS = {
    "RECONNAISSANCE": "Passive/active info gathering: headers, banners, tech stack, robots, sitemap.",
    "DISCOVERY": "Enumerate endpoints and parameters that can be reached safely.",
    "VULNERABILITY_ANALYSIS": "Validate weak controls and probe for likely weaknesses.",
    "EXPLOITATION": "Attempt safe exploitation paths such as default credentials.",
    "POST_EXPLOITATION": "Collect clear proof of compromise and impact evidence.",
    "COMPLETED": "Simulation finished.",
}

PHASE_ORDER = [
    "RECONNAISSANCE",
    "DISCOVERY",
    "VULNERABILITY_ANALYSIS",
    "EXPLOITATION",
    "POST_EXPLOITATION",
    "COMPLETED",
]

PHASE_ALIASES = {
    "ENUMERATION": "DISCOVERY",
    "PRIVILEGE_ESCALATION": "POST_EXPLOITATION",
    "PROOF_OF_COMPROMISE": "POST_EXPLOITATION",
}

STAGE_LABELS = {
    "RECONNAISSANCE": "planning_recon",
    "DISCOVERY": "scanning",
    "VULNERABILITY_ANALYSIS": "scanning",
    "EXPLOITATION": "exploitation",
    "POST_EXPLOITATION": "maintaining_access_payload",
    "COMPLETED": "proof_of_compromise",
}

ALLOWED_ACTIONS = [
    "HTTPHeaderFetch",
    "TechnologyFingerprint",
    "RobotsAndSitemap",
    "EndpointDiscovery",
    "EndpointProbe",
    "ParameterDiscovery",
    "VulnerabilityScanning",
    "SQLInjectionProbe",
    "ExploitAttempt",
    "PayloadGeneration",
    "ExploitScriptGeneration",
    "ProofOfCompromise",
]


def _is_payload_or_script_action(action_name: str) -> bool:
    token = (action_name or "").strip().lower()
    return any(
        marker in token
        for marker in ("payload", "script", "exploit", "shell", "poc")
    )


def _normalize_phase(phase: str) -> str:
    upper = (phase or "RECONNAISSANCE").upper()
    return PHASE_ALIASES.get(upper, upper)


def _available_action_names(decision_input: DecisionInput) -> List[str]:
    available = decision_input.available_commands or []
    names = [
        str(command.get("name", "")).strip()
        for command in available
        if isinstance(command, dict) and str(command.get("name", "")).strip()
    ]
    return names or list(ALLOWED_ACTIONS)


def _next_phase(phase: str) -> str:
    upper = _normalize_phase(phase)
    try:
        idx = PHASE_ORDER.index(upper)
        return PHASE_ORDER[idx + 1] if idx + 1 < len(PHASE_ORDER) else "COMPLETED"
    except ValueError:
        return "ENUMERATION"


def _phase_desc(phase: str) -> str:
    return PHASE_DESCRIPTIONS.get(_normalize_phase(phase), "Unknown phase.")


def _result_block(decision_input: DecisionInput) -> str:
    lr = decision_input.last_result
    if not lr:
        return "Previous command: none (first action)."
    status = "SUCCESS" if lr.success else "FAILED"
    output = lr.raw_output or lr.output_summary or ""
    error_line = f"\nError: {lr.error}" if lr.error else ""
    output_line = f"\nOutput:\n{output}" if output else "\nOutput: (empty)"
    return f"Previous command result: {status}{error_line}{output_line}"


def _findings_block(decision_input: DecisionInput) -> str:
    findings = decision_input.findings or {}
    if not findings:
        return "Findings: none yet."
    return "Findings: " + json.dumps(findings, separators=(",", ":"))


def _memory_block(decision_input: DecisionInput) -> str:
    memory = decision_input.memory or {}
    if not memory:
        return "Agent memory: none yet."
    return "Agent memory: " + json.dumps(memory, separators=(",", ":"), default=str)


def _history_block(decision_input: DecisionInput) -> str:
    past = decision_input.past_actions or []
    if not past:
        return "History: none."
    lines = [
        f"  {a.action_type}({json.dumps(a.parameters, separators=(',', ':'))})"
        for a in past[-3:]
    ]
    return "History (last 3):\n" + "\n".join(lines)


def _target_block(decision_input: DecisionInput) -> str:
    if not decision_input.known_services:
        return "Target: unknown."
    svc = decision_input.known_services[0]
    return f"Target: {svc.name} ({svc.protocol or 'tcp'}://{svc.endpoint or '?'})"


def _target_lock_rules(decision_input: DecisionInput) -> str:
    if not decision_input.known_services:
        return "Target lock: use only the explicit target above. Do not invent hosts, subnets, or extra URLs."
    svc = decision_input.known_services[0]
    endpoint = svc.endpoint or "unknown"
    return (
        f"Target lock: use the exact target reference '{endpoint}' when building parameters. "
        "Do not invent new IP ranges, hosts, domains, or substitute a different target."
    )


def build_recommendation_prompt(
    decision_input: DecisionInput,
    next_step_hint: dict = None,
) -> str:
    phase = _normalize_phase(decision_input.phase or "RECONNAISSANCE")
    next_p = _next_phase(phase)
    actions = ", ".join(_available_action_names(decision_input))

    if next_step_hint:
        hint_action = next_step_hint.get("action_type") or next_step_hint.get("action")
        hint_params = next_step_hint.get("parameters") or {}
        task_line = (
            f"Execute planned step: action='{hint_action}', "
            f"hint_parameters={json.dumps(hint_params, separators=(',', ':'))}. "
            "Refine parameters from output. If impossible, pick closest alternative."
        )
    else:
        task_line = (
            f"Choose the single best next action from: {actions}. "
            "Base your choice on the previous command output and findings. "
            "If FAILED, retry with corrected parameters or pick an alternative."
        )

    schema = (
        '{\n'
        '  "action_type": "<action name>",\n'
        '  "parameters": {},\n'
        '  "rationale": "<one sentence: what was found and why this action>",\n'
        f'  "suggested_next_phase": "<{phase} to stay, or {next_p} to advance>",\n'
        '  "phase_reason": "<one sentence: why this phase decision>"\n'
        '}'
    )

    return (
        f"Phase: {phase} - {_phase_desc(phase)}\n"
        f"{_target_block(decision_input)}\n\n"
        f"{_result_block(decision_input)}\n\n"
        f"{_findings_block(decision_input)}\n\n"
        f"{_memory_block(decision_input)}\n\n"
        f"{_history_block(decision_input)}\n\n"
        f"Task: {task_line}\n\n"
        f"{_target_lock_rules(decision_input)}\n"
        "Output compactness rules: rationale <= 12 words; phase_reason <= 12 words.\n"
        f"Phase rule: stay in {phase} if actions remain; suggest {next_p} if phase objective is complete.\n\n"
        f"Respond ONLY with this JSON (no markdown, no extra text):\n{schema}"
    )


def build_plan_prompt(decision_input: DecisionInput) -> str:
    phase = _normalize_phase(decision_input.phase or "RECONNAISSANCE")
    stage_label = STAGE_LABELS.get(phase, "planning_recon")
    done = [a.action_type for a in (decision_input.past_actions or [])]
    available_actions = _available_action_names(decision_input)
    payload_script_actions = [a for a in available_actions if _is_payload_or_script_action(a)]

    schema = (
        '{\n'
        '  "rationale": "<one sentence phase plan rationale>",\n'
        '  "steps": [\n'
        '    {"step_number": 1, "action_type": "<action>", "parameters": {}, '
        '"rationale": "<one sentence referencing output or findings>", '
        '"stage_label": "<planning_recon|scanning|exploitation|maintaining_access_payload|proof_of_compromise>", '
        '"execution_type": "<command|script>", "script_language": "<python|bash|null>", '
        '"script_content": "<script or null>", "artifact_refs": [], '
        '"success_criteria": "<evidence-driven completion criteria>"}\n'
        '  ]\n'
        '}'
    )

    return (
        f"Phase: {phase} - {_phase_desc(phase)}\n"
        f"{_target_block(decision_input)}\n\n"
        f"{_result_block(decision_input)}\n\n"
        f"{_findings_block(decision_input)}\n\n"
        f"{_memory_block(decision_input)}\n\n"
        f"Task: Generate an ordered plan for the CURRENT PHASE ONLY: {phase}.\n"
        f"- Do not plan later phases yet.\n"
        f"- Include multiple concrete commands for this phase when they are relevant.\n"
        f"- Prefer broader information gathering before narrower retries.\n"
        f"- Use as many distinct allowed actions for this phase as are useful.\n"
        f"- Keep weak or redundant retries out of the plan.\n"
        f"- Use real values from findings/output for parameters (IPs, URLs, ports, paths).\n"
        f"- Keep parameters compact and reuse the exact target reference above.\n"
        f"- Skip already done in this attack: {done}\n"
        f"- If Findings include operator_rejected_plans, avoid repeating the rejected step sequence unless no safe alternative exists.\n"
        f"- Each step rationale must reference actual output or findings.\n"
        f"- Keep rationale fields short (<= 14 words each).\n"
        f"- If only one action is available, return one step.\n"
        f"- If multiple actions are available, sequence them to maximize useful data collection.\n"
        f"- In EXPLOITATION or POST_EXPLOITATION, include payload/script-oriented actions when available.\n"
        f"- If payload/script actions exist, prioritize at least one before final proof collection.\n"
        f"- Use stage_label '{stage_label}' for this phase.\n"
        f"- Set execution_type='script' with script_content when script/payload generation is useful.\n"
        f"- Set artifact_refs as a list (can be empty) and include clear success_criteria.\n"
        f"{_target_lock_rules(decision_input)}\n\n"
        f"Allowed actions for this phase: {', '.join(available_actions)}\n\n"
        f"Payload/Script-capable actions currently available: {', '.join(payload_script_actions) if payload_script_actions else 'none'}\n\n"
        f"Respond ONLY with this JSON (no markdown):\n{schema}"
    )


def is_first_step(decision_input: DecisionInput) -> bool:
    return not decision_input.past_actions and decision_input.last_result is None


def build_step_mapping_prompt(
    decision_input: DecisionInput,
    next_step_hint: dict = None,
) -> str:
    phase = _normalize_phase(decision_input.phase or "RECONNAISSANCE")
    next_p = _next_phase(phase)

    lr = decision_input.last_result
    status = "SUCCESS" if lr and lr.success else "FAILED"
    output = (lr.raw_output or lr.output_summary or "(empty)") if lr else "(empty)"
    error_line = f"\nError: {lr.error}" if lr and lr.error else ""

    if next_step_hint:
        hint_action = next_step_hint.get("action_type") or next_step_hint.get("action", "")
        hint_params = next_step_hint.get("parameters") or {}
        task_line = (
            f"Map previous output to the next planned step.\n"
            f"Next step: action='{hint_action}', "
            f"base_parameters={json.dumps(hint_params, separators=(',', ':'))}.\n"
            "Refine parameters using values found in the output above (IPs, paths, ports). "
            "If the step is impossible given the output, choose the closest alternative."
        )
    else:
        actions = ", ".join(_available_action_names(decision_input))
        task_line = (
            f"Based only on the output above, choose the single best next action "
            f"from: {actions}."
        )

    schema = (
        '{\n'
        '  "action_type": "<action name>",\n'
        '  "parameters": {},\n'
        '  "rationale": "<one sentence referencing the output above>",\n'
        f'  "suggested_next_phase": "<{phase} or {next_p}>",\n'
        '  "phase_reason": "<one sentence>"\n'
        '}'
    )

    return (
        f"Phase: {phase}\n"
        f"Previous result: {status}{error_line}\n"
        f"Output:\n{output}\n\n"
        f"Task: {task_line}\n\n"
        f"{_target_lock_rules(decision_input)}\n"
        "Output compactness rules: rationale <= 12 words; phase_reason <= 12 words.\n"
        f"Respond ONLY with this JSON (no markdown, no extra text):\n{schema}"
    )


def build_narrative_prompt(decision_input: DecisionInput) -> str:
    phase = _normalize_phase(decision_input.phase or "RECONNAISSANCE")
    next_p = _next_phase(phase)

    return (
        f"Phase: {phase} - {_phase_desc(phase)}\n"
        f"{_target_block(decision_input)}\n\n"
        f"{_result_block(decision_input)}\n\n"
        f"{_findings_block(decision_input)}\n\n"
        f"{_memory_block(decision_input)}\n\n"
        f"Task: Write a 3-5 bullet Markdown status update for the security dashboard.\n"
        f"Cover: what just ran, what was found, next step, whether to advance to {next_p}.\n"
        f"Reference actual output above. No filler."
    )
