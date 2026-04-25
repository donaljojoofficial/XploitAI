import json
import logging
from urllib.parse import urlsplit
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.db import transaction
from core.models import AttackerExecutor, ExecutionTask

logger = logging.getLogger(__name__)


def _normalize_host_target(target):
    raw = str(target or "").strip()
    if not raw:
        return "127.0.0.1"
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    return parsed.hostname or raw

@csrf_exempt
@require_http_methods(["POST"])
def heartbeat(request):
    """
    Receives heartbeat from executor.
    Input: { "name": "<executor_name>" }
    Infers IP from request.META["REMOTE_ADDR"]
    """
    try:
        data = json.loads(request.body)
        name = data.get("name")
        
        if not name:
            return JsonResponse({"error": "Missing 'name'"}, status=400)
            
        # Infer IP address
        ip_address = request.META.get("REMOTE_ADDR")
        
        # Update or create executor record
        AttackerExecutor.objects.update_or_create(
            name=name,
            defaults={
                "ip_address": ip_address,
                "last_heartbeat": timezone.now(),
                "status": "CONNECTED"
            }
        )
        
        return JsonResponse({"status": "ok"})
        
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    except Exception as e:
        logger.error(f"Heartbeat error: {e}")
        return JsonResponse({"error": str(e)}, status=500)

def _resolve_command(action_name, parameters):
    """
    Maps abstract actions to concrete shell commands.
    """
    params = parameters or {}
    
    if action_name == "scan_target":
        target = _normalize_host_target(params.get("ip") or params.get("target") or "127.0.0.1")
        return f"nmap -sV {target}"
    elif action_name == "ping_target":
        target = params.get("ip") or params.get("target") or "127.0.0.1"
        return f"ping -c 4 {target}"
    elif action_name == "PassiveRecon":
        target = params.get("target_domain") or "localhost"
        return f"whois {target}"
    elif action_name == "ServiceEnumeration":
        target = _normalize_host_target(params.get("target_host") or params.get("target") or "localhost")
        return f"nmap -sV {target}"
    elif action_name == "ExploitAttempt":
        vuln_id = params.get("vulnerability_id", "UNKNOWN_VULN")
        target = params.get("target_host", "localhost")
        return f"echo 'SIMULATING EXPLOIT {vuln_id} on {target}'"
    elif action_name == "HTTPHeaderFetch":
        target = params.get("target_url") or params.get("url") or "http://localhost"
        return f"curl -I {target}"
    elif action_name == "TechnologyFingerprint":
        target = params.get("target_url") or params.get("url") or "http://localhost"
        return f"whatweb {target}"
    elif action_name == "EndpointDiscovery":
        target = params.get("target_url") or params.get("url") or "http://localhost"
        return f"curl {target}/robots.txt"
        
    return f"echo 'No command mapping defined for action: {action_name}'"

@require_http_methods(["GET"])
def get_tasks(request):
    """
    Returns pending execution tasks.
    Claims the oldest pending task and returns it as a single-item list.
    """
    try:
        with transaction.atomic():
            task = (
                ExecutionTask.objects
                .select_for_update(skip_locked=True)
                .filter(status="PENDING")
                .order_by("created_at")
                .first()
            )

            if not task:
                return JsonResponse([], safe=False)

            params = task.parameters or {}
            cmd = params.get("command") or _resolve_command(task.action_name, params)

            task.status = "RUNNING"
            task.save(update_fields=["status", "updated_at"])

        return JsonResponse([{
            "id": task.id,
            "action_name": task.action_name,
            "command": cmd,
            "parameters": params,
            "limits": params.get("limits", {}) if isinstance(params, dict) else {}
        }], safe=False)
    except Exception as e:
        logger.error(f"Get tasks error: {e}")
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def report_result(request, task_id):
    """
    Receives execution result for a specific task.
    Input: { "task_id": <int>, "status": "...", "exit_code": <int>, "stdout": "...", "stderr": "...", "duration_seconds": <float>, "artifacts": [...], "error_message": "..." }
    """
    try:
        data = json.loads(request.body)
        
        if not task_id:
            return JsonResponse({"error": "Missing task_id"}, status=400)
            
        try:
            task = ExecutionTask.objects.get(id=task_id)
            task.status = data.get("status", "UNKNOWN")
            stdout = data.get("stdout", "")
            stderr = data.get("stderr", "")
            task.output = {
                "exit_code": data.get("exit_code"),
                "stdout": stdout,
                "stderr": stderr,
                "duration_seconds": data.get("duration_seconds", 0),
                "artifacts": data.get("artifacts", []),
            }
            task.error_message = data.get("error_message", "") or stderr
            task.save()
            
            return JsonResponse({"status": "recorded"})
            
        except ExecutionTask.DoesNotExist:
            return JsonResponse({"error": "Task not found"}, status=404)
            
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    except Exception as e:
        logger.error(f"Report result error: {e}")
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def report_result_legacy(request):
    """
    Legacy endpoint for receiving execution result.
    Input: { "task_id": <int>, "status": "...", "output": "..." }
    """
    try:
        data = json.loads(request.body)
        task_id = data.get("task_id")
        status = data.get("status")
        output = data.get("output", "")
        
        if not task_id or not status:
            return JsonResponse({"error": "Missing task_id or status"}, status=400)
            
        try:
            task = ExecutionTask.objects.get(id=task_id)
            task.status = status
            task.output = output
            task.completed_at = timezone.now()
            task.save()
            
            return JsonResponse({"status": "recorded"})
            
        except ExecutionTask.DoesNotExist:
            return JsonResponse({"error": "Task not found"}, status=404)
            
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    except Exception as e:
        logger.error(f"Report result error: {e}")
        return JsonResponse({"error": str(e)}, status=500)
