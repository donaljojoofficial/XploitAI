#!/usr/bin/env python
"""
Integration test: Full execution loop simulation.
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

from core.models import AttackState, Command, ExecutionResult
from state.state_manager import StateManager
from ai.planner import AIPlanner
from executor.local_executor import run_command
from parser.output_parser import parse_output

# Create test attack state
attack_state, _ = AttackState.objects.get_or_create(
    id=1000,
    defaults={
        "name": "Integration Test",
        "current_phase": "RECONNAISSANCE",
        "state_data": {"target": "http://localhost"},
    }
)

print("=" * 60)
print("INTEGRATION TEST: Full Execution Loop")
print("=" * 60)
print(f"\n[*] Attack State: {attack_state.name}")
print(f"[*] Initial Phase: {attack_state.current_phase}")
print(f"[*] Target: {attack_state.state_data.get('target')}\n")

state_manager = StateManager(attack_state_id=attack_state.id)
planner = AIPlanner()

# Simulate 3 execution steps
for step in range(3):
    print(f"\n--- Step {step + 1} ---")
    
    # Get available commands
    current_state = state_manager.get_current_state_for_planner()
    available = list(state_manager.get_available_commands(current_state.get('current_phase')))
    
    if not available:
        print("[!] No more commands available, stopping.")
        break
    
    print(f"[*] Available commands: {len(available)}")
    for cmd in available:
        print(f"    - [{cmd.id}] {cmd.name}")
    
    # Get AI decision
    decision = planner.get_next_command(state_manager)
    if not decision:
        print("[!] AI planner returned no decision, stopping.")
        break
    
    cmd_id = decision.get('command_id')
    reason = decision.get('reason')
    
    print(f"[+] AI Decision: Command ID {cmd_id}")
    print(f"    Reason: {reason}")
    
    # Execute command
    cmd_obj = Command.objects.get(id=cmd_id)
    target = current_state.get('target')
    
    try:
        command_str = cmd_obj.command_template.format(target=target)
        print(f"[>] Executing: {command_str}")
        
        result = run_command(command_str)
        status = "SUCCESS" if result.get('returncode') == 0 else "FAILED"
        
        print(f"[OK] Status: {status}")
        if result.get('stdout'):
            print(f"    Output: {result.get('stdout')[:100]}...")
        
        # Parse findings
        findings = parse_output(cmd_obj.name, result.get('stdout', ''))
        if findings:
            print(f"[+] Findings: {findings}")
            state_manager.update_state_with_findings(findings)
        
        # Store execution result
        exec_result = ExecutionResult.objects.create(
            command=cmd_obj,
            attack_state=attack_state,
            target=target,
            status=status,
            stdout=result.get('stdout', ''),
            stderr=result.get('stderr', ''),
            findings=findings or {},
        )
        
        # Mark command as completed
        state_manager.add_completed_command(cmd_id)
        
        print(f"[*] Execution Result ID: {exec_result.id}")
    
    except Exception as e:
        print(f"[!] Error: {e}")
        break

print("\n" + "=" * 60)
print("TEST COMPLETE")
print("=" * 60)

# Final state
final_state = AttackState.objects.get(id=attack_state.id)
results_count = ExecutionResult.objects.filter(attack_state=final_state).count()
print(f"\n[+] Total execution results recorded: {results_count}")
print(f"[+] Completed commands: {final_state.state_data.get('completed_commands', [])}")
print(f"[+] Findings: {final_state.state_data.get('findings', {})}")
