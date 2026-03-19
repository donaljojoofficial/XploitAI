import logging
from django.db import transaction

from core.models import Action, ActionResult, AttackState

logger = logging.getLogger(__name__)


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

        # Prefer command IDs from state_data to avoid exposing raw command templates.
        completed_commands = state_obj.state_data.get("completed_commands", [])
        if not isinstance(completed_commands, list):
            completed_commands = []

        # Backward compatibility: if state_data has no completed_commands,
        # reconstruct from ExecutionResult records which have the command FK.
        if not completed_commands:
            from core.models import ExecutionResult
            completed_commands = list(
                ExecutionResult.objects.filter(
                    attack_state=state_obj,
                    status__in=["SUCCESS", "FAILED"],  # both count as done
                )
                .exclude(command=None)
                .values_list("command_id", flat=True)
                .distinct()
            )
            if completed_commands:
                # Persist back so future calls are fast
                state_obj.state_data["completed_commands"] = list(completed_commands)
                state_obj.save(update_fields=["state_data"])

        return {
            "target": target_ref,
            "current_phase": state_obj.current_phase,
            "completed_commands": completed_commands,
            "findings": state_obj.state_data.get("findings", {}),
        }

    def get_available_commands(self, phase_name: str):
        """Returns Command queryset for phase excluding already completed IDs."""
        from core.models import Command, Phase

        # Normalize phase name to lowercase for database lookup
        normalized_phase = phase_name.lower() if phase_name else ""

        try:
            phase = Phase.objects.get(name__iexact=normalized_phase)
        except Phase.DoesNotExist:
            logger.warning(f"Phase not found: {phase_name} (normalized: {normalized_phase})")
            return Command.objects.none()

        state = self.get_attack_state()
        completed = state.state_data.get("completed_commands", []) or []
        return Command.objects.filter(phase=phase).exclude(id__in=completed)

    @transaction.atomic
    def add_completed_command(self, command_id: int):
        state = self.get_attack_state()
        if not state.state_data or not isinstance(state.state_data, dict):
            state.state_data = {}
        completed = state.state_data.get("completed_commands", [])
        if not isinstance(completed, list):
            completed = []
        if command_id not in completed:
            completed.append(command_id)
        state.state_data["completed_commands"] = completed
        state.save(update_fields=["state_data", "updated_at"])

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