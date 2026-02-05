"""
Executor API Views — XploitAI

Responsibilities:
- Serve execution tasks to the polling executor daemon.
- Receive execution results and update task/action state.
- Act as the interface between the AI controller (via DB) and the external executor.
"""

import json
import logging
from django.http import JsonResponse, HttpRequest
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_http_methods
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.db import transaction

from core.models import ExecutionTask, Action

logger = logging.getLogger(__name__)

@csrf_exempt
@require_http_methods(["GET"])
def get_next_task(request: HttpRequest) -> JsonResponse:
    """
    API endpoint for the executor daemon to poll for pending tasks.
    Returns the oldest PENDING task and marks it as RUNNING.
    """
    # We use a transaction to ensure atomic "get and lock" behavior
    with transaction.atomic():
        # Select the oldest pending task
        # select_for_update() locks the row to prevent race conditions if multiple executors poll
        task = ExecutionTask.objects.select_for_update(skip_locked=True).filter(
            status='PENDING'
        ).order_by('created_at').first()

        if not task:
            return JsonResponse({"task": None})

        # Mark as running
        task.status = 'RUNNING'
        task.started_at = timezone.now()
        task.save()

        logger.info(f"Dispatching task {task.id} ({task.action_name}) to executor.")

        return JsonResponse({
            "task": {
                "id": task.id,
                "action_name": task.action_name,
                "command": getattr(task, 'command', ''),  # specific command if available
                "parameters": task.parameters,
            }
        })

@csrf_exempt
@require_POST
def report_result(request: HttpRequest, task_id: str = None) -> JsonResponse:
    """
    API endpoint for the executor to report task completion or failure.
    Updates ExecutionTask and the parent Action.
    """
    try:
        data = json.loads(request.body)
        task_id = data.get("task_id")
        status = data.get("status")  # Expected: COMPLETED or FAILED
        output = data.get("output", "")
        error_msg = data.get("error", "")

        if not task_id or not status:
            return JsonResponse({"error": "Missing 'task_id' or 'status'"}, status=400)

        task = get_object_or_404(ExecutionTask, id=task_id)

        # Update Task
        task.status = status
        task.output = output
        task.error_message = error_msg
        task.completed_at = timezone.now()
        task.save()

        logger.info(f"Task {task.id} finished with status {status}.")

        # Propagate status to the parent Action if linked
        if task.action:
            action = task.action
            if status == 'COMPLETED':
                action.status = 'COMPLETED'
            elif status == 'FAILED':
                action.status = 'FAILED'
            
            action.save()
            logger.info(f"Updated parent Action {action.id} status to {action.status}.")

        return JsonResponse({"status": "ok"})

    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON payload"}, status=400)
    except Exception as e:
        logger.error(f"Exception in report_result: {str(e)}")
        return JsonResponse({"error": "Internal server error"}, status=500)