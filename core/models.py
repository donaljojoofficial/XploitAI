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


ACTION_STATUS_CHOICES = [
    ("PENDING", "Pending"),
    ("EXECUTED", "Executed"),
    ("REJECTED", "Rejected"),
]


class Action(models.Model):
    """
    Represents a single action proposed by the AI agent during an attack.

    Each action is a discrete step in the penetration testing lifecycle,
    like scanning a host or attempting to exploit a vulnerability. Actions
    must be approved by the Policy Engine before they can be executed.
    """

    attack_state = models.ForeignKey(
        AttackState,
        on_delete=models.CASCADE,
        related_name="actions",
        help_text="The attack simulation this action belongs to.",
    )

    name = models.CharField(
        max_length=100,
        help_text="The name of the action to be executed (e.g., 'NmapScan').",
    )

    description = models.TextField(
        blank=True,
        help_text="A brief description of what this action does.",
    )

    parameters = models.JSONField(
        default=dict,
        help_text="The parameters required to execute the action.",
    )

    status = models.CharField(
        max_length=20,
        choices=ACTION_STATUS_CHOICES,
        default="PENDING",
        help_text="The current status of the action.",
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="The timestamp when the action was created.",
    )

    class Meta:
        verbose_name = "Action"
        verbose_name_plural = "Actions"
        ordering = ["created_at"]

    def __str__(self):
        return f"{self.name} on {self.attack_state.name} ({self.status})"


class ActionResult(models.Model):
    """
    Stores the outcome of an executed Action.

    This model provides a detailed record of what happened when an action
    was performed, including whether it succeeded, what data it produced,
    and any relevant log messages.
    """

    action = models.OneToOneField(
        Action,
        on_delete=models.CASCADE,
        related_name="result",
        help_text="The action that produced this result.",
    )

    success = models.BooleanField(
        default=False,
        help_text="Indicates whether the action executed successfully.",
    )

    output = models.JSONField(
        default=dict,
        help_text="Structured data returned by the action (e.g., open ports).",
    )

    log_message = models.TextField(
        blank=True,
        help_text="A human-readable log of the action's outcome.",
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="The timestamp when the result was recorded.",
    )

    class Meta:
        verbose_name = "Action Result"
        verbose_name_plural = "Action Results"
        ordering = ["-created_at"]

    def __str__(self):
        status = "Success" if self.success else "Failure"
        return f"Result for '{self.action.name}' ({status})"


# -----------------------
# Attack Timeline (Phase 1)
# -----------------------

TIMELINE_EVENT_TYPES = [
    ("DECISION", "Decision Proposed"),
    ("POLICY_APPROVED", "Policy Approved"),
    ("POLICY_REJECTED", "Policy Rejected"),
    ("EXECUTION", "Execution"),
    ("STATE_UPDATE", "State Update"),
    ("PHASE_TRANSITION", "Phase Transition"),
]


class AttackTimelineEvent(models.Model):
    """
    Represents a single event in the attack timeline for visualization.

    The timeline is an append-only log of notable events (decisions, policy
    outcomes, execution results, and state/phase changes). It enables the
    dashboard to render a chronological view of the simulated attack without
    requiring complex joins at read time.
    """

    attack_state = models.ForeignKey(
        AttackState,
        on_delete=models.CASCADE,
        related_name="timeline",
        help_text="The attack simulation this timeline event belongs to.",
    )

    # Optional linkage to a specific action (if applicable)
    action = models.ForeignKey(
        Action,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="timeline_events",
        help_text="Related action if this event is tied to a specific action.",
    )

    event_type = models.CharField(
        max_length=32,
        choices=TIMELINE_EVENT_TYPES,
        help_text="The type/category of this timeline event.",
    )

    phase = models.CharField(
        max_length=50,
        choices=KILL_CHAIN_PHASES,
        help_text="The kill-chain phase at the time of the event.",
    )

    message = models.TextField(
        help_text="A concise, human-readable description of the event.",
    )

    data = models.JSONField(
        default=dict,
        help_text="Optional structured data relevant to this event.",
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="The timestamp when the event was recorded.",
    )

    class Meta:
        verbose_name = "Attack Timeline Event"
        verbose_name_plural = "Attack Timeline Events"
        ordering = ["created_at"]
        indexes = [
            models.Index(fields=["attack_state", "created_at"]),
            models.Index(fields=["event_type"]),
        ]

    def __str__(self):
        return (
            f"[{self.get_event_type_display()}] "
            f"{self.attack_state.name} @ {self.created_at:%Y-%m-%d %H:%M:%S}"
        )
