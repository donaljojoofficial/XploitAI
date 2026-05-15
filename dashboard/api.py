"""
Dashboard API — XploitAI

Provides JSON data endpoints for frontend visualizations and chat helpers.
"""

import json

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_GET, require_POST
from django.core.serializers.json import DjangoJSONEncoder

from core.models import Action, AttackState, DefenderAlert, AttackTarget
from dashboard.chat_service import DashboardChatService


@login_required(login_url="login")
@require_GET
def interaction_timeline(request, attack_id: int) -> JsonResponse:
    """
    Return a combined timeline of Attacker Actions and Defender Alerts.

    This endpoint enables the frontend to visualize the interplay between
    autonomous AI decisions and defender detections.

    Args:
        request: The HTTP request.
        attack_id: The ID of the AttackState to visualize.
    """
    state = get_object_or_404(AttackState, pk=attack_id, owner=request.user)

    # 1. Fetch Attacker Actions
    actions = Action.objects.filter(attack_state=state).values(
        'id', 'name', 'status', 'created_at', 'description'
    )

    # 2. Fetch Defender Alerts
    alerts = DefenderAlert.objects.filter(attack_state=state).values(
        'id', 'rule_id', 'severity', 'created_at', 'description'
    )

    timeline = []

    # 3. Normalize and Merge Actions
    for action in actions:
        timeline.append({
            'event_type': 'ATTACKER_ACTION',
            'timestamp': action['created_at'],
            'id': action['id'],
            'label': action['name'],
            'status': action['status'],
            'details': action['description'],
            'severity': None  # Actions don't have severity
        })

    # 4. Normalize and Merge Alerts
    for alert in alerts:
        timeline.append({
            'event_type': 'DEFENDER_ALERT',
            'timestamp': alert['created_at'],
            'id': alert['id'],
            'label': alert['rule_id'],
            'status': 'DETECTED',
            'details': alert['description'],
            'severity': alert['severity']
        })

    # 5. Sort by Timestamp (Chronological Order)
    # Handle potential None timestamps gracefully, though models should enforce them
    timeline.sort(key=lambda x: x['timestamp'].isoformat() if x['timestamp'] else "")

    return JsonResponse({
        'attack_state_id': state.id,
        'event_count': len(timeline),
        'timeline': timeline
    }, encoder=DjangoJSONEncoder)

@login_required(login_url="login")
@require_GET
def target_list(request) -> JsonResponse:
    """
    Return a list of available targets for the dashboard.
    """
    targets = list(AttackTarget.objects.filter(owner=request.user).values(
        'id', 'name', 'ip_address', 'operating_system', 'is_active'
    ))
    return JsonResponse({'targets': targets}, encoder=DjangoJSONEncoder)


@login_required(login_url="login")
@require_POST
def attack_chat_ask(request) -> JsonResponse:
    try:
        payload = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        return JsonResponse({"success": False, "message": "Invalid JSON payload."}, status=400)

    attack_id = payload.get("attack_id")
    message = str(payload.get("message") or "").strip()
    phase_key = str(payload.get("phase_key") or "").strip() or None
    include_recommendations = bool(payload.get("include_recommendations", True))

    if not attack_id:
        return JsonResponse({"success": False, "message": "attack_id is required."}, status=400)
    if not message:
        return JsonResponse({"success": False, "message": "message is required."}, status=400)
    try:
        attack_id = int(attack_id)
    except (TypeError, ValueError):
        return JsonResponse({"success": False, "message": "attack_id must be an integer."}, status=400)

    service = DashboardChatService(request)
    response = service.ask(
        attack_id=attack_id,
        message=message,
        phase_key=phase_key,
        include_recommendations=include_recommendations,
    )
    if not response.get("selected_run"):
        return JsonResponse({"success": False, **response}, status=404)
    return JsonResponse({"success": True, **response}, encoder=DjangoJSONEncoder)


@login_required(login_url="login")
@require_POST
def attack_chat_reset(request) -> JsonResponse:
    try:
        payload = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        return JsonResponse({"success": False, "message": "Invalid JSON payload."}, status=400)
    attack_id = payload.get("attack_id")
    if not attack_id:
        return JsonResponse({"success": False, "message": "attack_id is required."}, status=400)
    try:
        attack_id = int(attack_id)
    except (TypeError, ValueError):
        return JsonResponse({"success": False, "message": "attack_id must be an integer."}, status=400)
    DashboardChatService(request).reset(attack_id)
    return JsonResponse({"success": True, "attack_id": attack_id})
