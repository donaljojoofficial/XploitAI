# core/models.py

from django.db import models
from django.utils import timezone

# According to project_scope.md, the cyber attack lifecycle has several phases.
# These will be used as states in our simulation.
KILL_CHAIN_PHASES = [
    ("RECONNAISSANCE", "Reconnaissance"),
    ("ENUMERATION", "Enumeration"),
    ("EXPLOITATION", "Exploitation"),
    ("PRIVILEGE_ESCALATION", "Privilege Escalation"),
    ("PROOF_OF_COMPROMISE", "Proof of Compromise"),
    ("COMPLETED", "Completed"),
]


class AttackState(models.Model):
    """
    Represents the central state of a single attack simulation.

    This model tracks the progress of an attack through the kill chain and
    stores all relevant data discovered or generated during the simulation.
    It acts as the "single source of truth" for a given attack scenario.
    """

    name = models.CharField(
        max_length=255,
        help_text="A unique name for this attack simulation scenario.",
    )

    current_phase = models.CharField(
        max_length=50,
        choices=KILL_CHAIN_PHASES,
        default="RECONNAISSANCE",
        help_text="The current phase of the attack in the kill chain.",
    )

    state_data = models.JSONField(
        default=dict,
        help_text="A JSON object storing dynamic data about the attack state, "
                  "e.g., discovered hosts, vulnerabilities, compromised accounts.",
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="The timestamp when the simulation was created.",
    )

    updated_at = models.DateTimeField(
        auto_now=True,
        help_text="The timestamp of the last state update.",
    )

    class Meta:
        verbose_name = "Attack State"
        verbose_name_plural = "Attack States"
        ordering = ["-updated_at"]

    def __str__(self):
        """
        Returns a string representation of the attack state.
        """
        return f"{self.name} ({self.get_current_phase_display()})"

    def advance_phase(self, new_phase: str):
        """
        Advances the attack to a new phase, if valid.
        """
        phase_names = [phase[0] for phase in KILL_CHAIN_PHASES]
        if new_phase not in phase_names:
            raise ValueError(f"Invalid phase: {new_phase}")

        self.current_phase = new_phase
        self.save(update_fields=["current_phase", "updated_at"])

    def update_state_data(self, new_data: dict):
        """
        Updates the state_data field with new information.
        """
        self.state_data.update(new_data)
        self.save(update_fields=["state_data", "updated_at"])
