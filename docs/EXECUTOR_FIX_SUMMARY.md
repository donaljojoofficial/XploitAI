# Executor Daemon Connection Timeout Fix

## Problem

The executor daemon was connecting to the Django controller but timing out when
polling for tasks. The root cause was a contract mismatch between the daemon and
the executor API.

## Root Cause

The daemon expected a single task object from the controller, but the API
returned a list of task objects. Result submission also needed a task-specific
endpoint so completed task output could be tied back to the correct
`ExecutionTask`.

## Fixes Applied

### 1. Endpoint URL

The daemon now polls the task collection endpoint:

```text
/api/executor/tasks/
```

### 2. API Response Parsing

The daemon now handles an array response and extracts task data from each item
instead of assuming the response body is a single task object.

### 3. Result Submission

The executor API includes a task-specific result endpoint:

```text
/api/executor/tasks/<task_id>/result/
```

The legacy result endpoint is retained for compatibility:

```text
/api/executor/results/
```

### 4. URL Routing

`executor/urls.py` routes heartbeat, task polling, task-specific results, and
legacy result submission under `/api/executor/`.

## Files Modified

- `executor/daemon.py` - endpoint URL and response parsing.
- `executor/api_views.py` - result submission endpoint support.
- `executor/urls.py` - task-specific result route.
- `scripts/checks/check_executor_selection.py` - manual verification script.

## Verification

The fixes verify that the executor can:

1. Use the correct task polling endpoint.
2. Handle array response format from the API.
3. Extract task data correctly from response items.
4. Submit results to the correct task-specific endpoint.
5. Maintain backward compatibility with the legacy result endpoint.

## Expected Outcome

After applying these fixes, the executor daemon should poll tasks, execute the
selected work item, and report the result without timing out because of response
format or endpoint mismatches.
