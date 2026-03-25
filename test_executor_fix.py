#!/usr/bin/env python3
"""
Test script to verify the executor selection fix.
This script tests that the system correctly uses the selected executor instead of always defaulting to local execution.
"""

import os
import sys
import django
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'xploitai.settings')
django.setup()

from core.models import AttackState, AttackerExecutor, AttackTarget, AttackContext
from dashboard.views import start_attack
from django.http import HttpRequest, QueryDict

User = get_user_model()

def test_executor_selection():
    """Test that the system correctly selects between local and remote executors."""
    print("Testing executor selection fix...")
    
    # Create test user
    user = User.objects.create_user(username='testuser', password='testpass', is_staff=True)
    user.save()
    
    # Create test target
    target = AttackTarget.objects.create(
        name="Test Target",
        ip_address="192.168.1.100",
        operating_system="Ubuntu 20.04",
        is_active=True
    )
    target.save()
    
    # Create test executor (connected)
    executor = AttackerExecutor.objects.create(
        name="Test Executor",
        ip_address="192.168.1.50",
        status=AttackerExecutor.Status.CONNECTED
    )
    executor.save()
    
    # Create test request for remote execution
    request = HttpRequest()
    request.method = 'POST'
    request.user = user
    
    # Simulate POST data for remote execution
    post_data = QueryDict(mutable=True)
    post_data['executor_id'] = str(executor.id)
    post_data['target_id'] = str(target.id)
    post_data['llm_provider'] = 'gemini'
    request.POST = post_data
    
    # Call start_attack view
    response = start_attack(request)
    
    # Check that the attack state was created with remote execution mode
    attack_state = AttackState.objects.latest('created_at')
    print(f"Attack State Name: {attack_state.name}")
    print(f"Execution Mode: {attack_state.state_data.get('execution_mode', 'NOT SET')}")
    print(f"Autonomy Status: {attack_state.autonomy_status}")
    print(f"Stop Reason: {attack_state.stop_reason}")
    
    # Verify remote execution was selected
    if attack_state.state_data.get('execution_mode') == 'remote':
        print("✅ SUCCESS: Remote execution mode correctly selected")
        print(f"   - Attack state name includes executor name: {'Test Executor' in attack_state.name}")
        print(f"   - Autonomy status is RUNNING: {attack_state.autonomy_status == 'RUNNING'}")
        print(f"   - Stop reason mentions remote execution: {'remote' in attack_state.stop_reason.lower()}")
    else:
        print("❌ FAILURE: Remote execution mode not selected")
        print(f"   - Expected: remote, Got: {attack_state.state_data.get('execution_mode')}")
        return False
    
    # Test local execution (no executor selected)
    request2 = HttpRequest()
    request2.method = 'POST'
    request2.user = user
    
    post_data2 = QueryDict(mutable=True)
    post_data2['target_id'] = str(target.id)
    post_data2['llm_provider'] = 'gemini'
    request2.POST = post_data2
    
    response2 = start_attack(request2)
    
    # Check that the attack state was created with local execution mode
    attack_state2 = AttackState.objects.latest('created_at')
    print(f"\nSecond Attack State Name: {attack_state2.name}")
    print(f"Execution Mode: {attack_state2.state_data.get('execution_mode', 'NOT SET')}")
    print(f"Autonomy Status: {attack_state2.autonomy_status}")
    
    # Verify local execution was selected
    if attack_state2.state_data.get('execution_mode') == 'local':
        print("✅ SUCCESS: Local execution mode correctly selected when no executor chosen")
        print(f"   - Attack state name includes 'Local Run': {'Local Run' in attack_state2.name}")
        print(f"   - Autonomy status is IDLE (waiting for service): {attack_state2.autonomy_status == 'IDLE'}")
    else:
        print("❌ FAILURE: Local execution mode not selected")
        print(f"   - Expected: local, Got: {attack_state2.state_data.get('execution_mode')}")
        return False
    
    # Test disconnected executor (should fall back to local)
    executor.status = AttackerExecutor.Status.DISCONNECTED
    executor.save()
    
    request3 = HttpRequest()
    request3.method = 'POST'
    request3.user = user
    
    post_data3 = QueryDict(mutable=True)
    post_data3['executor_id'] = str(executor.id)
    post_data3['target_id'] = str(target.id)
    post_data3['llm_provider'] = 'gemini'
    request3.POST = post_data3
    
    response3 = start_attack(request3)
    
    # Check that the attack state was created with local execution mode (fallback)
    attack_state3 = AttackState.objects.latest('created_at')
    print(f"\nThird Attack State Name: {attack_state3.name}")
    print(f"Execution Mode: {attack_state3.state_data.get('execution_mode', 'NOT SET')}")
    print(f"Autonomy Status: {attack_state3.autonomy_status}")
    
    # Verify local execution was selected as fallback
    if attack_state3.state_data.get('execution_mode') == 'local':
        print("✅ SUCCESS: Local execution mode correctly selected as fallback for disconnected executor")
        print(f"   - Attack state name includes 'Local Run': {'Local Run' in attack_state3.name}")
        print(f"   - Autonomy status is IDLE (waiting for service): {attack_state3.autonomy_status == 'IDLE'}")
    else:
        print("❌ FAILURE: Local execution mode not selected as fallback")
        print(f"   - Expected: local, Got: {attack_state3.state_data.get('execution_mode')}")
        return False
    
    print("\n🎉 All tests passed! The executor selection fix is working correctly.")
    return True

if __name__ == "__main__":
    try:
        success = test_executor_selection()
        if success:
            print("\n✅ Test completed successfully!")
            sys.exit(0)
        else:
            print("\n❌ Test failed!")
            sys.exit(1)
    except Exception as e:
        print(f"\n❌ Test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)