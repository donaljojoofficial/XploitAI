"""
Agentic architecture contract for XploitAI.

This module keeps the product architecture explicit instead of scattering the
concept of "agentic AI" across templates and controller code. It is intentionally
side-effect free so views, planners, docs, and tests can all import it safely.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


AGENTIC_ARCHITECTURE_VERSION = "agentic-control-plane-v1"


@dataclass(frozen=True)
class AgentNode:
    key: str
    name: str
    role: str
    state_key: str
    signal: str


@dataclass(frozen=True)
class AgentLoop:
    key: str
    name: str
    description: str


AGENT_NODES = (
    AgentNode(
        key="orchestrator",
        name="Orchestrator Agent",
        role="Selects the next objective and coordinates the run loop.",
        state_key="autonomy_status",
        signal="Control",
    ),
    AgentNode(
        key="planner",
        name="Planner Agent",
        role="Builds phase plans from target context, findings, and available tools.",
        state_key="current_plan",
        signal="Reasoning",
    ),
    AgentNode(
        key="policy",
        name="Policy Guard",
        role="Approves, rejects, or pauses proposed actions before execution.",
        state_key="plan_approved",
        signal="Safety",
    ),
    AgentNode(
        key="executor",
        name="Executor Agent",
        role="Runs approved commands through local, SSH, or daemon execution paths.",
        state_key="execution_mode",
        signal="Action",
    ),
    AgentNode(
        key="memory",
        name="Memory Agent",
        role="Persists findings, retries, evidence, history, and learned context.",
        state_key="findings",
        signal="Learning",
    ),
    AgentNode(
        key="reviewer",
        name="Reviewer Agent",
        role="Explains results, summarizes evidence, and recommends follow-up work.",
        state_key="level_history",
        signal="Reflection",
    ),
)


AGENT_LOOPS = (
    AgentLoop(
        key="sense",
        name="Sense",
        description="Collect target context, executor health, alerts, and recent outputs.",
    ),
    AgentLoop(
        key="plan",
        name="Plan",
        description="Generate a bounded plan with concrete steps and success criteria.",
    ),
    AgentLoop(
        key="guard",
        name="Guard",
        description="Apply policy, scope, safety checks, and human approval gates.",
    ),
    AgentLoop(
        key="act",
        name="Act",
        description="Dispatch only approved work to the selected executor channel.",
    ),
    AgentLoop(
        key="learn",
        name="Learn",
        description="Parse results into memory, findings, phase reviews, and reports.",
    ),
)


def _node_status(node: AgentNode, state_data: dict[str, Any], attack_state: Any = None) -> str:
    if node.key == "orchestrator":
        status = getattr(attack_state, "autonomy_status", "") if attack_state else ""
        return status or "IDLE"
    if node.key == "planner":
        plan = getattr(attack_state, "current_plan", None) if attack_state else None
        return "READY" if isinstance(plan, dict) and plan.get("steps") else "STANDBY"
    if node.key == "policy":
        return "APPROVED" if state_data.get("plan_approved") else "GATED"
    if node.key == "executor":
        return str(state_data.get("execution_mode") or "local").upper()
    if node.key == "memory":
        findings = state_data.get("findings") if isinstance(state_data.get("findings"), dict) else {}
        return f"{len(findings)} SIGNALS"
    if node.key == "reviewer":
        reviews = state_data.get("level_history") or state_data.get("phase_reviews") or []
        return f"{len(reviews)} REVIEWS"
    return "READY"


def build_agentic_architecture_snapshot(attack_state: Any = None) -> dict[str, Any]:
    """Return a UI-safe snapshot of the current agentic runtime."""
    state_data = getattr(attack_state, "state_data", None)
    if not isinstance(state_data, dict):
        state_data = {}

    return {
        "version": AGENTIC_ARCHITECTURE_VERSION,
        "nodes": [
            {
                **asdict(node),
                "status": _node_status(node, state_data, attack_state),
            }
            for node in AGENT_NODES
        ],
        "loops": [asdict(loop) for loop in AGENT_LOOPS],
        "runtime": {
            "provider": state_data.get("llm_provider") or "auto",
            "execution_mode": state_data.get("execution_mode") or "local",
            "progression_mode": state_data.get("progression_mode") or "manual",
            "plan_approved": bool(state_data.get("plan_approved")),
        },
    }
