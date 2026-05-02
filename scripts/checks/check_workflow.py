#!/usr/bin/env python
"""
Quick test to verify the command-selection and execution workflow.
"""
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
import django

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

load_dotenv(PROJECT_ROOT / ".env")
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'xploitai.settings')
django.setup()

from core.models import AttackState, Command
from state.state_manager import StateManager
from ai.planner import AIPlanner

# Create or get a test attack state
attack_state, created = AttackState.objects.get_or_create(
    id=999,
    defaults={
        "name": "Test Workflow",
        "current_phase": "RECONNAISSANCE",
        "state_data": {"target": "http://dvwa.local"},
    }
)

print(f"[*] AttackState: {attack_state.name} (id={attack_state.id})")
print(f"[*] Current phase: {attack_state.current_phase}")
print(f"[*] Target: {attack_state.state_data.get('target')}")

state_manager = StateManager(attack_state_id=attack_state.id)

# Get current state for planner
current_state = state_manager.get_current_state_for_planner()
print(f"\n[*] Current state for planner:")
print(f"    - Phase: {current_state.get('current_phase')}")
print(f"    - Target: {current_state.get('target')}")
print(f"    - Completed commands: {current_state.get('completed_commands')}")

# Get available commands for current phase
phase_name = current_state.get('current_phase')
available = list(state_manager.get_available_commands(phase_name))
print(f"\n[*] Available commands for phase '{phase_name}': {len(available)}")
for cmd in available:
    print(f"    - [{cmd.id}] {cmd.name}: {cmd.description}")

if not available:
    print("[!] ERROR: No commands available for this phase!")
    sys.exit(1)

# Test planner
planner = AIPlanner()
decision = planner.get_next_command(state_manager)

if decision:
    print(f"\n[+] AI Decision:")
    print(f"    - Command ID: {decision.get('command_id')}")
    print(f"    - Command Name: {decision.get('command_name')}")
    print(f"    - Reason: {decision.get('reason')}")
else:
    print("[!] ERROR: Planner returned no decision!")
    sys.exit(1)

# Verify command exists
cmd_id = decision.get('command_id')
cmd = Command.objects.filter(id=cmd_id).first()
if cmd:
    print(f"\n[+] Command template retrieved:")
    print(f"    - {cmd.command_template}")
else:
    print(f"[!] ERROR: Command ID {cmd_id} not found!")
    sys.exit(1)

print("\n[+] Workflow test PASSED!")
