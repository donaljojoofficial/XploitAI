import json
import logging
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from core.models import AttackerExecutor, ExecutionTask

logger = logging.getLogger(__name__)

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
        target = params.get("ip") or params.get("target") or "127.0.0.1"
        return f"nmap -sV {target}"
    elif action_name == "ping_target":
        target = params.get("ip") or params.get("target") or "127.0.0.1"
        return f"ping -c 4 {target}"
    elif action_name == "PassiveRecon":
        target = params.get("target_domain") or "localhost"
        return f"whois {target}"
    elif action_name == "ServiceEnumeration":
        target = params.get("target_host") or "localhost"
        return f"nmap -sV {target}"
    elif action_name == "ExploitAttempt":
        vuln_id = params.get("vulnerability_id", "UNKNOWN_VULN")
        target = params.get("target_host", "localhost")
        return f"echo 'SIMULATING EXPLOIT {vuln_id} on {target}'"
        
    return f"echo 'No command mapping defined for action: {action_name}'"

@require_http_methods(["GET"])
def get_tasks(request):
    """
    Returns pending execution tasks.
    Output: [ { "id": 1, "action_name": "...", "command": "..." }, ... ]
    """
    try:
        tasks = ExecutionTask.objects.filter(status="PENDING").values(
            "id", "action_name", "parameters"
        )
        
        task_list = []
        for t in tasks:
            task_list.append({
                "id": t["id"],
                "action_name": t["action_name"],
                "command": _resolve_command(t["action_name"], t.get("parameters")),
                "parameters": t.get("parameters", {}),
                "limits": {}  # Default limits
            })
            
        return JsonResponse(task_list, safe=False)
    except Exception as e:
        logger.error(f"Get tasks error: {e}")
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def report_result(request):
    """
    Receives execution result.
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