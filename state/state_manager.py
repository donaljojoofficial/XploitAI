from django.db import transaction

from core.models import Action, ActionResult, AttackState


class StateManager:
    """
    Manages reading and writing the attack state to the database,
    acting as an abstraction layer over the Django models.
    """

    def __init__(self, attack_state_id: int):
        self.attack_state_id = attack_state_id

    def get_attack_state(self) -> AttackState:
        """Retrieves the full AttackState object."""
        return AttackState.objects.get(id=self.attack_state_id)

    def get_current_state_for_planner(self) -> dict:
        """Constructs the simplified state dictionary for the AI planner."""
        state_obj = self.get_attack_state()
        if not state_obj.state_data:
            state_obj.state_data = {}

        target_ref = state_obj.state_data.get("target")
        if not target_ref:
            target_ref = (
                state_obj.state_data.get("planner_context", {})
                .get("targets", [{}])[0]
                .get("primary_ref", "unknown")
            )

        completed_actions = list(
            Action.objects.filter(attack_state=state_obj, status="COMPLETED")
            .order_by("created_at")
            .values_list("name", flat=True)
        )

        return {
            "target": target_ref,
            "current_phase": state_obj.current_phase,
            "completed_actions": completed_actions,
            "findings": state_obj.state_data.get("findings", {}),
        }

    @transaction.atomic
    def update_state_with_findings(self, findings: dict):
        """Merges new findings into the state_data JSONB field."""
        if not findings:
            return

        state = self.get_attack_state()
        if not isinstance(state.state_data, dict):
            state.state_data = {}
        if "findings" not in state.state_data:
            state.state_data["findings"] = {}

        state.state_data["findings"].update(findings)
        state.save(update_fields=["state_data"])

    @transaction.atomic
    def record_action(self, name: str, params: dict, result: dict, reasoning: str) -> Action:
        """Records a completed or failed action and its result."""
        state = self.get_attack_state()
        status = "COMPLETED" if result.get("returncode") == 0 else "FAILED"

        action = Action.objects.create(attack_state=state, name=name, parameters=params, reasoning=reasoning, status=status)
        ActionResult.objects.create(action=action, success=(status == "COMPLETED"), output=result, log_message=result.get("stderr") or f"Action {status}")

        # Keep state_data aligned with the completed action sequence
        if not state.state_data or not isinstance(state.state_data, dict):
            state.state_data = {}
        state.state_data.setdefault("completed_actions", [])
        state.state_data["completed_actions"].append(name)
        state.save(update_fields=["state_data"])

        return action