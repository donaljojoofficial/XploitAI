"""
AI Decision Engine implementation.
"""
from typing import List, Tuple

from .schemas import DecisionRequest, Decision, DecisionInput
from .memory import AgentMemory


class RuleBasedDecisionEngine:
    """
    Deterministic, rule-based decision engine with memory integration.
    """

    def __init__(self, memory: AgentMemory) -> None:
        self.memory = memory

    def decide(self, request: DecisionRequest) -> Decision:
        """Evaluate state and memory to propose the next action."""
        input_data = request.decision_input
        
        # 1. Generate Candidates
        candidates = self._generate_candidates(input_data)
        
        # 2. Evaluate with Memory
        best_action = None
        best_score = -1.0
        best_rationale = "No valid action found."

        for action in candidates:
            score, rationale = self._evaluate_action(action)
            
            if score > best_score:
                best_score = score
                best_action = action
                best_rationale = rationale

        # 3. Return Decision
        if best_action:
            return Decision(
                action_type=best_action["type"],
                parameters=best_action["params"],
                rationale=best_rationale
            )

        return Decision(
            action_type="wait",
            parameters={"duration": 5},
            rationale="No suitable actions found; waiting."
        )

    def _generate_candidates(self, input_data: DecisionInput) -> List[dict]:
        """Generate potential actions based on phase and known services."""
        candidates = []
        
        # Simple heuristic generation based on phase
        if input_data.phase == "recon":
            for service in input_data.known_services:
                candidates.append({
                    "type": "scan_service",
                    "params": {"target": service.endpoint or service.name}
                })
        
        elif input_data.phase == "exploit":
            for service in input_data.known_services:
                candidates.append({
                    "type": "exploit_service",
                    "params": {"target": service.endpoint or service.name}
                })
                
        return candidates

    def _evaluate_action(self, action: dict) -> Tuple[float, str]:
        """Score an action based on memory history.
        
        Scoring:
        - 1.0: Standard
        - 1.2: Previously successful (preferred)
        - 0.1: Repeated failures (deprioritized)
        - 0.0: Repeated rejections (avoided)
        """
        stats = self.memory.analyze_history(action["type"], action["params"])
        
        if stats["rejections"] > 0:
            return 0.0, f"Skipped {action['type']}: Rejected by policy {stats['rejections']} times."
            
        if stats["failures"] >= 3:
             return 0.1, f"Deprioritized {action['type']}: Failed {stats['failures']} times."
             
        if stats["successes"] > 0:
            return 1.2, f"Selected {action['type']}: Previously successful."
            
        return 1.0, f"Selected {action['type']}: Standard priority."