"""
Dashboard Views — XploitAI (Phase 1)

Responsibilities (per architecture.md):
- Visualization only (no decision logic, no execution logic)
- Minimal HTML responses for quick inspection of simulation state

Design:
- Provide two basic endpoints:
  - index: list of AttackState objects
  - attack_detail: details for a specific AttackState with actions and timeline
- Keep deterministic and simple formatting; no external assets or JS required.
- Expose urlpatterns in this module for easy inclusion by the project URLs.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpRequest, HttpResponse
from django.views.decorators.http import require_POST
from django.utils import timezone

from core.models import AttackState, Action, AttackTimelineEvent, ExecutionTask, DefenderAlert, AttackerExecutor, AttackTarget, AttackContext
from ai.autonomy import AutonomousController

logger = logging.getLogger(__name__)


def _get_unified_events(state: AttackState) -> list[dict]:
    """Helper to aggregate all temporal events for timeline and replay."""
    actions = Action.objects.filter(attack_state=state)
    events = AttackTimelineEvent.objects.filter(attack_state=state)
    tasks = ExecutionTask.objects.filter(action__attack_state=state)
    alerts = DefenderAlert.objects.filter(attack_state=state)

    unified = []

    # 1. AI Actions (Decisions)
    for a in actions:
        unified.append({
            'dt': a.created_at,
            'source': 'AI',
            'type': 'DECISION',
            'desc': f"Planned: {a.name}",
            'data': {'reasoning': a.reasoning, 'parameters': a.parameters},
        })

    # 2. System Events
    for e in events:
        unified.append({
            'dt': e.created_at,
            'source': 'SYSTEM',
            'type': e.get_event_type_display(),
            'desc': e.message,
            'data': e.data,
        })

    # 3. Defender Alerts
    for a in alerts:
        unified.append({
            'dt': a.created_at,
            'source': 'DEFENDER',
            'type': f"ALERT {a.severity}",
            'desc': f"{a.rule_id}: {a.description}",
            'data': {'recommendation': a.recommendation},
        })

    # 4. Execution Tasks
    for t in tasks:
        unified.append({
            'dt': t.created_at,
            'source': 'EXECUTOR',
            'type': 'TASK_QUEUED',
            'desc': f"Queued: {t.action_name}",
            'data': t.parameters,
        })
        if t.status in ('COMPLETED', 'FAILED'):
             unified.append({
                'dt': t.updated_at,
                'source': 'EXECUTOR',
                'type': f"TASK_{t.status}",
                'desc': f"Finished: {t.action_name}",
                'data': t.output or {'error': t.error_message},
            })

    unified.sort(key=lambda x: x['dt'])
    return unified


def index(request: HttpRequest) -> HttpResponse:
    """
    Displays the main dashboard using a Django template.
    Shows the latest simulation by default.
    """
    attack_state = AttackState.objects.order_by('-updated_at').first()

    if attack_state:
        actions = Action.objects.filter(attack_state=attack_state).order_by('-created_at')[:10]
        tasks = ExecutionTask.objects.filter(action__attack_state=attack_state).order_by('-created_at')[:10]
        alerts = DefenderAlert.objects.filter(attack_state=attack_state).order_by('-created_at')[:5]
    else:
        actions = []
        tasks = []
        alerts = []

    executors = AttackerExecutor.objects.all().order_by('-last_heartbeat')
    targets = AttackTarget.objects.all().order_by('name')

    context = {
        'attack_state': attack_state,
        'actions': actions,
        'tasks': tasks,
        'alerts': alerts,
        'executors': executors,
        'targets': targets,
    }
    return render(request, 'dashboard/index.html', context)


def attack_detail(request: HttpRequest, pk: int) -> HttpResponse:
    """Show details for a specific AttackState, including actions and timeline."""
    state = get_object_or_404(AttackState, pk=pk)

    actions = Action.objects.filter(attack_state=state).order_by("created_at")
    tasks = ExecutionTask.objects.filter(action__attack_state=state).order_by("-created_at")
    alerts = DefenderAlert.objects.filter(attack_state=state).order_by("-created_at")

    consecutive_failures = 0
    for a in actions.reverse():
        if a.status == 'FAILED':
            consecutive_failures += 1
        else:
            break

    interaction_events = []
    for a in actions:
        interaction_events.append({'ts': a.created_at, 'type': 'ATTACKER', 'obj': a})
    for alert in alerts:
        interaction_events.append({'ts': alert.created_at, 'type': 'DEFENDER', 'obj': alert})
    interaction_events.sort(key=lambda x: x['ts'])

    unified_events = _get_unified_events(state)

    context = {
        'state': state,
        'actions': actions,
        'tasks': tasks,
        'alerts': alerts,
        'unified_events': unified_events,
        'consecutive_failures': consecutive_failures,
        'interaction_events': interaction_events,
    }
    return render(request, 'dashboard/attack_detail.html', context)


def attack_replay(request: HttpRequest, pk: int) -> HttpResponse:
    """Show a sequential replay of the attack lifecycle."""
    state = get_object_or_404(AttackState, pk=pk)
    unified_events = _get_unified_events(state)
    context = {
        'state': state,
        'unified_events': unified_events,
    }
    return render(request, 'dashboard/replay.html', context)


@require_POST
def start_attack(request: HttpRequest) -> HttpResponse:
    """
    Handles the 'Start Autonomous Attack' trigger from the dashboard.
    Creates a new AttackState and AttackContext, then starts the controller.
    """
    executor_id = request.POST.get('executor_id')
    target_id = request.POST.get('target_id')

    if not executor_id or not target_id:
        return redirect('dashboard_index')

    # 1. Create new Attack State
    state = AttackState.objects.create(
        name=f"Autonomous Run {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}",
        current_phase="RECONNAISSANCE",
        autonomy_status="IDLE"
    )

    # 2. Create Operational Context
    executor = get_object_or_404(AttackerExecutor, pk=executor_id)
    target = get_object_or_404(AttackTarget, pk=target_id)

    # Close any existing active contexts
    AttackContext.objects.filter(status__in=['READY', 'RUNNING']).update(
        status='STOPPED',
        stop_reason='Superseded by new attack start',
        stopped_at=timezone.now()
    )

    AttackContext.objects.create(
        attacker_executor=executor,
        target=target,
        status='READY'
    )

    # 3. Initialize and Start Controller
    controller = AutonomousController(attack_state_id=state.id)
    controller.start()

    return redirect('dashboard_index')
