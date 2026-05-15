"""
Executor Heartbeat API — XploitAI (Phase 6)

Responsibilities:
- Handle heartbeat signals from the Attacker Executor daemon.
- Update the AttackerExecutor model state (status, last_heartbeat).
- Auto-register new executors if they don't exist.

This is a machine-to-machine API endpoint.
"""

import json
import logging
from django.http import JsonResponse, HttpRequest
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.utils import timezone
from core.models import AttackerExecutor

logger = logging.getLogger(__name__)

@csrf_exempt
@require_POST
def heartbeat(request: HttpRequest) -> JsonResponse:
    """
    Receives heartbeat from executor daemon.
    Updates status to CONNECTED and refreshes last_heartbeat timestamp.
    """
    try:
        data = json.loads(request.body)
        name = data.get("name")
        ip_address = data.get("ip_address") or request.META.get("REMOTE_ADDR")

        if not name:
            return JsonResponse({"error": "Missing 'name'"}, status=400)

        # Register or update the executor status
        executor, created = AttackerExecutor.objects.update_or_create(
            name=name,
            owner=None,
            defaults={
                "ip_address": ip_address,
                "status": AttackerExecutor.Status.CONNECTED,
                "last_heartbeat": timezone.now(),
            }
        )

        action = "registered" if created else "updated"
        logger.info(f"Executor '{name}' heartbeat received ({action}).")

        return JsonResponse({
            "status": "ok",
            "executor": executor.name,
            "connection_status": executor.status,
            "timestamp": executor.last_heartbeat.isoformat()
        })

    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON payload"}, status=400)
    except Exception as e:
        logger.error(f"Heartbeat processing failed: {str(e)}")
        return JsonResponse({"error": "Internal server error"}, status=500)
