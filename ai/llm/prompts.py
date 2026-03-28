"""
Shared prompt construction logic for LLM adapters.
"""
import json
from ai.schemas import DecisionInput
from typing import List, Optional

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
    "ProofOfCompromise",
]


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
    # compact JSON — no indent, saves ~30% tokens vs indent=2
    return "Findings: " + json.dumps(findings, separators=(',', ':'))


def _history_block(decision_input: DecisionInput) -> str:
    past = decision_input.past_actions or []
    if not past:
        return "History: none."
    lines = [f"  {a.action_type}({json.dumps(a.parameters, separators=(',', ':'))})"
             for a in past[-3:]]
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

    # NOTE: JSON schema uses f-string interpolation — phase values are real strings here
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
        f"Phase: {phase} — {_phase_desc(phase)}\n"
        f"{_target_block(decision_input)}\n\n"
        f"{_result_block(decision_input)}\n\n"
        f"{_findings_block(decision_input)}\n\n"
        f"{_history_block(decision_input)}\n\n"
        f"Task: {task_line}\n\n"
        f"{_target_lock_rules(decision_input)}\n"
        "Output compactness rules: rationale <= 12 words; phase_reason <= 12 words.\n"
        f"Phase rule: stay in {phase} if actions remain; suggest {next_p} if phase objective is complete.\n\n"
        f"Respond ONLY with this JSON (no markdown, no extra text):\n{schema}"
    )


def build_plan_prompt(decision_input: DecisionInput) -> str:
    phase = _normalize_phase(decision_input.phase or "RECONNAISSANCE")
    upper = phase.upper()
    try:
        start = PHASE_ORDER.index(upper)
    except ValueError:
        start = 0
    remaining = [p for p in PHASE_ORDER[start:] if p != "COMPLETED"]
    phase_guide = "\n".join(f"  {p}: {_phase_desc(p)}" for p in remaining)
    done = [a.action_type for a in (decision_input.past_actions or [])]

    schema = (
        '{\n'
        '  "rationale": "<one sentence overall plan rationale>",\n'
        '  "steps": [\n'
        '    {"step_number": 1, "action_type": "<action>", "parameters": {}, '
        '"rationale": "<one sentence referencing output or findings>"}\n'
        '  ]\n'
        '}'
    )

    return (
        f"Phase: {phase} — {_phase_desc(phase)}\n"
        f"{_target_block(decision_input)}\n\n"
        f"{_result_block(decision_input)}\n\n"
        f"{_findings_block(decision_input)}\n\n"
        f"Task: Generate a complete ordered cyber kill-chain plan from {phase} to PROOF_OF_COMPROMISE.\n"
        f"- Cover every remaining phase, not just the next action.\n"
        f"- Return 8 to 12 detailed steps when that many actions are available.\n"
        f"- Use as many distinct allowed actions as possible before ending the plan.\n"
        f"- Do not compress an entire phase into one generic step when multiple relevant actions exist.\n"
        f"- For reconnaissance and discovery, include multiple concrete substeps.\n"
        f"- For vulnerability analysis, include multiple validation steps before exploitation.\n"
        f"- Do not jump to exploitation until the plan has gathered enough evidence.\n"
        f"- Do not end at ProofOfCompromise unless exploitation evidence should exist first.\n"
        f"- Use only allowed actions from the list below. Never invent action names.\n"
        f"- Use real values from findings/output for parameters (IPs, URLs, ports).\n"
        f"- Keep parameters compact and reuse the exact target reference above.\n"
        f"- Skip already done: {done}\n"
        f"- Each step rationale must reference actual output or findings.\n"
        f"- Keep rationale fields short (<= 14 words each).\n"
        f"- The plan must feel like a real pentest workflow, not a 4-step outline.\n"
        f"{_target_lock_rules(decision_input)}\n\n"
        f"Phases remaining:\n{phase_guide}\n\n"
        f"Allowed actions: {', '.join(_available_action_names(decision_input))}\n\n"
        f"Respond ONLY with this JSON (no markdown):\n{schema}"
    )


def is_first_step(decision_input: DecisionInput) -> bool:
    """Return True when no previous action has been executed yet."""
    return not decision_input.past_actions and decision_input.last_result is None


def build_step_mapping_prompt(
    decision_input: DecisionInput,
    next_step_hint: dict = None,
) -> str:
    """
    Minimal prompt for non-first steps.

    Instead of resending the full context (findings, history, target, phase
    description, allowed-action list, etc.) we only send:
      - the previous command output (already truncated by ActionResultSummary)
      - the next planned step hint (if any)

    This keeps token usage as low as possible on free-quota APIs while still
    giving the model enough signal to refine parameters for the next action.

    Returns a JSON schema identical to build_recommendation_prompt so all
    existing parsers work unchanged.
    """
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
        f"Phase: {phase} — {_phase_desc(phase)}\n"
        f"{_target_block(decision_input)}\n\n"
        f"{_result_block(decision_input)}\n\n"
        f"{_findings_block(decision_input)}\n\n"
        f"Task: Write a 3-5 bullet Markdown status update for the security dashboard.\n"
        f"Cover: what just ran, what was found, next step, whether to advance to {next_p}.\n"
        f"Reference actual output above. No filler."
    )
