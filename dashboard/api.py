"""
Dashboard API — XploitAI

Provides JSON data endpoints for frontend visualizations, specifically
for the Attacker vs Defender interaction timeline.
"""

from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_GET
from django.core.serializers.json import DjangoJSONEncoder

from core.models import Action, AttackState, DefenderAlert


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
    state = get_object_or_404(AttackState, pk=attack_id)

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