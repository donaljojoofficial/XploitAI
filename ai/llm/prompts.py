"""
Shared prompt construction logic for LLM adapters.
"""
import json
from ai.schemas import DecisionInput
from typing import List


def build_recommendation_prompt(decision_input: DecisionInput, allowed_actions: List[str] = None, next_step_hint: dict = None) -> str:
    """Builds the prompt for the tactical decision recommendation."""
    # 1. Target Context
    target_context = "No active target identified."
    if decision_input.known_services:
        services = []
        for s in decision_input.known_services:
            endpoint = s.endpoint or "unknown"
            proto = s.protocol or "tcp"
            services.append(f"{s.name} ({proto}://{endpoint})")
        target_context = f"Known Services: {', '.join(services)}"

    # 2. State Object
    state_dict = {
        "phase": decision_input.phase,
        "target": decision_input.known_services[0].endpoint if decision_input.known_services else "unknown",
        "completed_commands": [a.action_type for a in decision_input.past_actions[-10:]],
        "findings": decision_input.findings or {},
        "available_commands": decision_input.available_commands or [],
    }

    if decision_input.last_result:
        state_dict["last_result"] = {
            "success": decision_input.last_result.success,
            "summary": decision_input.last_result.output_summary or "No output",
            "error": decision_input.last_result.error,
        }

    state_object = json.dumps(state_dict, indent=2)

    # 3. Phase Goal
    phase_goal = f"Advance the {decision_input.phase} phase by gathering new information or exploiting found vulnerabilities."
    if next_step_hint:
        phase_goal = (
            f"EXECUTE PLANNED STEP: {next_step_hint}. "
            "You MUST output this action. Refine parameters based on findings if needed."
        )

    prompt = (
        "You are assisting an automated security assessment system operating in an authorized laboratory environment using intentionally vulnerable applications for educational testing.\n"
        "The system performs assessments step-by-step, executes actions, summarizes the results, and updates its internal state before asking for further guidance.\n\n"
        "The objective is to progressively analyze the target application while keeping decisions efficient and focused on the most useful next step.\n\n"
        f"Target context:\n{target_context}\n\n"
        f"Current assessment state:\n{state_object}\n\n"
        "The state object summarizes everything currently known about the target system, including findings extracted from previous execution results.\n\n")
    
    if allowed_actions:
        action_list = "\n".join([f"- {action}" for action in allowed_actions])
        prompt += f"You MUST choose one of the following actions. You cannot choose any other action:\n{action_list}\n\n"

    prompt += (
        "The planner can operate in two modes.\n\n"
        "Mode:\ntactical\n\n"
        "When mode = \"tactical\"\n\n"
        f"The current phase goal is:\n{phase_goal}\n\n"
        "The AI must never propose raw commands. It must only choose from the provided metadata command catalog.\n"
        "Do not return any command templates or shell strings.\n\n"
        "Return JSON only in the format:\n"
        "{\n"
        "  \"action_type\": \"<name_of_the_command_from_catalog>\",\n"
        "  \"parameters\": {},\n"
        "  \"rationale\": \"<brief decision rationale>\"\n"
        "}"
    )
    return prompt


def build_plan_prompt(decision_input: DecisionInput) -> str:
    """Builds the prompt for generating a multi-step plan."""
    return (
        f"Context: {decision_input}\n"
        "Task: Create a multi-step security assessment plan for this educational scenario. Batch routine tasks where possible.\n"
        "You MUST include specific parameters (target_url, target_host, etc.) extracted from the Context.\n"
        "Allowed Actions & Parameters:\n"
        "- PassiveRecon (target_domain)\n"
        "- HTTPHeaderFetch (target_url)\n"
        "- EndpointDiscovery (target_url)\n"
        "- TechnologyFingerprint (target_url)\n"
        "- ServiceEnumeration (target_host)\n"
        "- ExploitAttempt (target_host, vulnerability_id)\n"
        "- PrivilegeEscalation (target_host)\n"
        "- ProofOfCompromise (evidence_tag)\n"
        "Schema: { \"steps\": [ { \"action_type\": \"<AllowedAction>\", \"parameters\": { \"<param>\": \"<value>\" }, \"rationale\": \"<user-friendly explanation>\" } ] }"
    )


def build_narrative_prompt(decision_input: DecisionInput) -> str:
    """Builds the prompt for generating the attack narrative."""
    return (
        f"Context: {decision_input}\n"
        "Task: Generate a detailed, real-time technical narrative of the ongoing security simulation. "
        "Describe the current phase, the status of findings, and the strategic outlook.\n"
        "Tone: Professional, objective, and educational.\n"
        "Format: Markdown. Use bold for emphasis and bullet points for lists. Structure for dashboard readability."
    )