"""
Concrete implementation of the AI Decision Engine.

Responsibilities:
- Provide deterministic, rule-based decision making.
- Support both single-step evaluation and multi-step planning.
- Adhere to the schemas defined in ai/schemas.py.
"""
from __future__ import annotations

from typing import List, Optional

from .schemas import Decision, DecisionRequest, Plan, PlanStep


class RuleBasedDecisionEngine:
    """
    A deterministic, rule-based decision engine for Phase 1 simulation.
    
    This engine does not use external LLMs. It uses static heuristics to
    recommend actions based on the current phase of the attack lifecycle.
    """

    def evaluate(self, request: DecisionRequest) -> Decision:
        """
        Returns a single decision based on the current state.
        
        For backward compatibility and single-step orchestration, this method
        generates a plan and returns the first actionable step.
        """
        # Generate a short plan
        plan = self.propose_plan(request, max_steps=1)
        
        if not plan.steps:
            return Decision(
                action_type="wait",
                parameters={},
                rationale="No valid actions available for the current state."
            )

        first_step = plan.steps[0]
        return Decision(
            action_type=first_step.action_type,
            parameters=first_step.parameters,
            rationale=first_step.rationale
        )

    def propose_plan(self, request: DecisionRequest, max_steps: int = 3) -> Plan:
        """
        Generates a multi-step plan based on the current phase.
        """
        phase = request.decision_input.phase
        steps: List[PlanStep] = []
        rationale = f"Standard operating procedure for {phase} phase."

        # Deterministic logic based on phase
        if phase == "recon":
            steps = [
                PlanStep(1, "scan_network", {"target": "192.168.1.0/24"}, "Discover active hosts."),
                PlanStep(2, "enumerate_services", {"target": "192.168.1.10"}, "Identify running services."),
                PlanStep(3, "vulnerability_scan", {"target": "192.168.1.10"}, "Check for known CVEs.")
            ]
        elif phase == "exploit":
            steps = [
                PlanStep(1, "attempt_exploit", {"cve": "CVE-2023-1234"}, "Attempt to exploit identified vulnerability."),
                PlanStep(2, "verify_access", {}, "Check if exploit was successful.")
            ]
        elif phase == "post_exploit":
            steps = [
                PlanStep(1, "dump_hashes", {}, "Extract credentials."),
                PlanStep(2, "persistence", {"method": "cron"}, "Establish persistence.")
            ]

        # Truncate to max_steps
        steps = steps[:max_steps]
        
        return Plan(steps=steps, rationale=rationale)