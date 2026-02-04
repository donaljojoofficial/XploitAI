"""
Approval Policy Definitions.

This module defines the categories of actions and phases that require
explicit human approval before execution. This implements the "Human Approval Gate"
architectural requirement for Phase 3.
"""
from typing import Set

# High-risk phases where any action requires approval
APPROVAL_REQUIRED_PHASES: Set[str] = {
    "PRIVILEGE_ESCALATION",
    "PROOF_OF_COMPROMISE",
}

# Specific high-risk action types (names) that require approval in any phase
APPROVAL_REQUIRED_ACTIONS: Set[str] = {
    "exploit_service",      # Active exploitation is risky
    "dump_credentials",     # Sensitive data access
    "lateral_movement",     # Spreading attack
    "exfiltrate_data",      # Data theft
    "install_persistence",  # System modification
}


def requires_human_approval(phase: str, action_name: str) -> bool:
    """
    Determine if an action requires human approval.

    Args:
        phase: The current kill-chain phase of the attack state (e.g., 'EXPLOITATION').
        action_name: The name/type of the action being proposed.

    Returns:
        True if the action is high-risk and requires approval, False otherwise.
    """
    # 1. Check Phase Risk
    if phase in APPROVAL_REQUIRED_PHASES:
        return True

    # 2. Check Action Risk
    if action_name in APPROVAL_REQUIRED_ACTIONS:
        return True

    return False