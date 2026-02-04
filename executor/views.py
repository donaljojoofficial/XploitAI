import json
import logging
from django.http import JsonResponse, HttpRequest, HttpResponseBadRequest, HttpResponseNotAllowed
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone

from core.models import ExecutionTask

logger = logging.getLogger(__name__)

@require_http_methods(["GET"])
def get_next_task(request: HttpRequest) -> JsonResponse:
    """
    Fetch the next pending execution task.
    
    Selects the oldest PENDING task, marks it as RUNNING, and returns its details.
    This is an atomic operation to prevent race conditions.
    """
    # Use a transaction to ensure we don't hand out the same task twice
    with transaction.atomic():
        # select_for_update locks the row until the transaction finishes
        task = (
            ExecutionTask.objects.filter(status="PENDING")
            .select_for_update(skip_locked=True)
            .order_by("created_at")
            .first()
        )

        if not task:
            return JsonResponse({"message": "No pending tasks"}, status=200)

        task.status = "RUNNING"
        task.save(update_fields=["status", "updated_at"])
        
        logger.info(f"Task {task.id} ({task.action_name}) claimed by executor")

        return JsonResponse({
            "task_id": task.id,
            "action_name": task.action_name,
            "parameters": task.parameters,
        })

@csrf_exempt  # No authentication yet, so we must exempt CSRF for external tools
@require_http_methods(["POST"])
def report_result(request: HttpRequest) -> JsonResponse:
    """
    Report the result of an execution task.
    
    Expects JSON body with:
    - task_id: int
    - status: "COMPLETED" | "FAILED"
    - output: dict/json (optional)
    - error_message: str (optional)
    """
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON body"}, status=400)

    task_id = data.get("task_id")
    status = data.get("status")
    output = data.get("output", {})
    error_message = data.get("error_message", "")

    if not task_id:
        return JsonResponse({"error": "Missing task_id"}, status=400)
    
    if status not in ["COMPLETED", "FAILED"]:
        return JsonResponse({"error": "Invalid status. Must be COMPLETED or FAILED"}, status=400)

    task = get_object_or_404(ExecutionTask, pk=task_id)

    # Update task state
    task.status = status
    task.output = output
    task.error_message = error_message
    # Note: updated_at is handled automatically by auto_now=True in the model
    task.save()

    logger.info(f"Task {task.id} reported as {status}")

    return JsonResponse({"status": "success", "message": "Task updated"})