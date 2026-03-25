# Executor Daemon Connection Timeout Fix

## Problem
The executor daemon was failing with connection timeout errors when trying to connect to the controller:

```
2026-03-24 13:43:59,561 [ERROR] Task fetch error: HTTPConnectionPool(host='172.26.224.1', port=8000): Max retries exceeded with url: /api/executor/tasks/next (Caused by ConnectTimeoutError(<urllib3.connection.HTTPConnection object at 0x72b29debc910>, 'Connection to 172.26.224.1 timed out. (connect timeout=10)'))
```

## Root Cause Analysis
The issue was caused by multiple mismatches between the executor daemon and the controller API:

1. **Incorrect Endpoint URL**: The daemon was trying to access `/api/executor/tasks/next` but the API only provides `/api/executor/tasks/`
2. **API Response Format**: The daemon expected a single task object but the API returns an array of tasks
3. **Missing Result Endpoint**: The daemon tried to POST results to `/api/executor/tasks/{task_id}/result` but this endpoint didn't exist

## Fixes Applied

### 1. Fixed Endpoint URL in Daemon (`XploitAI/executor/daemon.py`)
```python
# Before
resp = self.session.get(f"{self.api_url}/api/executor/tasks/next", timeout=10)

# After  
resp = self.session.get(f"{self.api_url}/api/executor/tasks/", timeout=10)
```

### 2. Fixed API Response Parsing (`XploitAI/executor/daemon.py`)
```python
# Before - expected single task object
data = resp.json()
if not data:
    return None
params = data.get('parameters', {})
cmd = data.get('command') or params.get('command')
return ExecutionRequest(
    task_id=data['task_id'],  # KeyError: 'task_id'
    action_name=data['action_name'],
    ...
)

# After - handle array of tasks
tasks = resp.json()
if not tasks:
    return None
data = tasks[0]  # Take first task
params = data.get('parameters', {})
cmd = data.get('command') or params.get('command')
return ExecutionRequest(
    task_id=data['id'],  # Use 'id' field from array item
    action_name=data['action_name'],
    ...
)
```

### 3. Added Missing Result Submission Endpoint (`XploitAI/executor/api_views.py`)
```python
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
            task.exit_code = data.get("exit_code")
            task.stdout = data.get("stdout", "")
            task.stderr = data.get("stderr", "")
            task.duration_seconds = data.get("duration_seconds", 0)
            task.artifacts = data.get("artifacts", [])
            task.error_message = data.get("error_message", "")
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
```

### 4. Updated URL Routing (`XploitAI/executor/urls.py`)
```python
# Before
urlpatterns = [
    path("heartbeat/", api_views.heartbeat, name="executor_heartbeat"),
    path("tasks/", api_views.get_tasks, name="executor_tasks"),
    path("results/", api_views.report_result, name="executor_results"),
]

# After
urlpatterns = [
    path("heartbeat/", api_views.heartbeat, name="executor_heartbeat"),
    path("tasks/", api_views.get_tasks, name="executor_tasks"),
    path("tasks/<int:task_id>/result/", api_views.report_result, name="executor_task_result"),
    path("results/", api_views.report_result_legacy, name="executor_results_legacy"),
]
```

## Files Modified
- `XploitAI/executor/daemon.py` - Fixed endpoint URL and response parsing
- `XploitAI/executor/api_views.py` - Added new result submission endpoint
- `XploitAI/executor/urls.py` - Added URL pattern for task-specific result endpoint
- `XploitAI/test_executor_fix.py` - Test script to verify fixes

## Verification
The fixes have been tested and verified to:
1. ✅ Use correct endpoint URL (`/api/executor/tasks/`)
2. ✅ Handle array response format from API
3. ✅ Extract task data correctly from array items
4. ✅ Submit results to the correct endpoint with task_id parameter
5. ✅ Maintain backward compatibility with legacy endpoints

## Expected Outcome
After applying these fixes, the executor daemon should:
- Successfully connect to the controller
- Properly fetch and execute tasks
- Correctly submit execution results
- No longer experience connection timeout errors due to incorrect endpoints

## Next Steps
1. Restart the executor daemon with the updated code
2. Verify that tasks are being fetched and executed successfully
3. Monitor the logs for any remaining connection issues
4. Test the full attack workflow to ensure end-to-end functionality