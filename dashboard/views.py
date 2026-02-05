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
from typing import Any, Iterable

from django.http import Http404, HttpRequest, HttpResponse
from django.urls import path
from django.utils.html import escape

from core.models import AttackState, Action, AttackTimelineEvent, ExecutionTask, DefenderAlert

logger = logging.getLogger(__name__)


def _html_page(title: str, body: str) -> str:
    return (
        "<!doctype html>"
        "<html lang='en'>"
        "<head>"
        f"<meta charset='utf-8'><title>{escape(title)}</title>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<style>"
        "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:2rem;}"
        "h1,h2,h3{margin:0.5rem 0;}"
        "a{color:#0b5ed7;text-decoration:none;}a:hover{text-decoration:underline;}"
        "code,pre{background:#f6f8fa;border-radius:6px;padding:0.2rem 0.4rem;}"
        "table{border-collapse:collapse;width:100%;margin:1rem 0;}"
        "th,td{border:1px solid #ddd;padding:0.5rem;text-align:left;}"
        ".muted{color:#6c757d;font-size:0.9rem;}"
        "</style>"
        "</head>"
        f"<body>{body}</body>"
        "</html>"
    )


def _render_memory_badge(data: Any) -> str:
    """Helper to render memory influence indicators if present in data."""
    if not data:
        return ""

    # Ensure data is a dict
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except (json.JSONDecodeError, TypeError):
            return ""

    if not isinstance(data, dict):
        return ""

    # Check direct keys (e.g. in Action.parameters)
    mem = data.get("_memory") or data.get("memory_influence") or data.get("memory_context")

    # If not found, check inside 'parameters' sub-dict (e.g. in PlanStep)
    if not mem and "parameters" in data:
        params = data["parameters"]
        if isinstance(params, str):
            try:
                params = json.loads(params)
            except (json.JSONDecodeError, TypeError):
                params = {}
        if isinstance(params, dict):
            mem = params.get("_memory") or params.get("memory_influence") or params.get("memory_context")

    if not mem:
        return ""

    # Determine label and text
    label = "MEMORY"
    text = str(mem)

    if isinstance(mem, dict):
        text = mem.get("description") or mem.get("reason") or str(mem)
        if "type" in mem:
            label = str(mem["type"]).upper()
    elif isinstance(mem, str):
        # Simple heuristics for cleaner badges
        lower_mem = mem.lower()
        if "fail" in lower_mem:
            label = "ADAPTATION"
        elif "success" in lower_mem:
            label = "REINFORCEMENT"
        elif "retry" in lower_mem:
            label = "RETRY"

    return (
        f"<div style='margin-top:0.3rem; font-size:0.85em; color:#563d7c;'>"
        f"<span style='background-color:#e2d9f3; border:1px solid #d5c8ed; border-radius:3px; padding:0.1rem 0.3rem; font-weight:bold; margin-right:0.3rem;'>🧠 {escape(label)}</span>"
        f"<span>{escape(text)}</span>"
        f"</div>"
    )


def _format_event_data(data: Any) -> str:
    """Helper to format event data, specifically rendering AI plans."""
    if not data:
        return ""

    # Robustness: Ensure data is a dict if it's a valid JSON string
    # This handles cases where SQLite/Django might return raw JSON strings.
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except (json.JSONDecodeError, TypeError):
            pass

    # Detect Plan structure: dict with 'steps' list
    if isinstance(data, dict) and "steps" in data and isinstance(data["steps"], list):
        steps = data["steps"]
        if not steps:
            return "<em>Empty Plan</em>"

        rows = []
        for i, step in enumerate(steps, 1):
            # Support both action_id (LLM) and action_type (internal) keys
            action = step.get("action_id") or step.get("action_type") or "Unknown"
            reason = step.get("reasoning", "")
            mem_badge = _render_memory_badge(step)
            rows.append(
                f"<tr><td>{i}</td><td>{escape(str(action))}</td><td>{escape(str(reason))}{mem_badge}</td></tr>"
            )

        return (
            "<div style='border:1px solid #eee; padding:0.5rem; border-radius:4px; background:#fafafa;'>"
            "<strong style='color:#2c3e50;'>AI Plan Proposal</strong>"
            "<table style='margin:0.5rem 0 0 0; background:#fff;'>"
            "<thead><tr><th>#</th><th>Action</th><th>Reasoning</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody>"
            "</table>"
            "</div>"
        )

    # Detect Policy Decision (nested or flat)
    policy = None
    if isinstance(data, dict):
        if "policy_decision" in data:
            policy = data["policy_decision"]
        elif "allowed" in data and "reason" in data:
            policy = data

    if policy:
        allowed = policy.get("allowed")
        reason = policy.get("reason", "No reason provided")
        approval = policy.get("approval_required", False)

        # Styles
        color = "#198754" if allowed else "#dc3545"  # Green/Red
        status_label = "ALLOWED" if allowed else "BLOCKED"

        approval_badge = ""
        if approval:
            approval_badge = (
                "<div style='margin-top:0.25rem; color:#fd7e14; font-weight:bold; font-size:0.9em;'>"
                "⚠️ Approval Required"
                "</div>"
            )

        return (
            f"<div style='border-left: 3px solid {color}; padding-left: 0.5rem; margin: 0.2rem 0;'>"
            f"<div style='color:{color}; font-weight:bold; font-size:0.9em;'>POLICY {status_label}</div>"
            f"<div style='font-size:0.95em;'>{escape(str(reason))}</div>"
            f"{approval_badge}"
            f"</div>"
        )

    # Detect Defender Alert
    if isinstance(data, dict) and "rule_id" in data and "severity" in data:
        severity = str(data["severity"]).upper()
        rule_id = str(data["rule_id"])
        description = str(data.get("description", ""))

        # Severity Colors (Bootstrap-ish)
        bg_map = {
            "CRITICAL": "#842029",  # Dark Red
            "HIGH": "#dc3545",      # Red
            "MEDIUM": "#fd7e14",    # Orange
            "LOW": "#ffc107",       # Yellow
            "INFO": "#0dcaf0",      # Cyan
        }
        fg_map = {"CRITICAL": "#fff", "HIGH": "#fff", "MEDIUM": "#000", "LOW": "#000", "INFO": "#000"}

        bg = bg_map.get(severity, "#6c757d")
        fg = fg_map.get(severity, "#fff")

        return (
            f"<div style='border:1px solid {bg}; border-radius:4px; overflow:hidden; margin:0.2rem 0;'>"
            f"<div style='background:{bg}; color:{fg}; padding:0.2rem 0.5rem; font-weight:bold; font-size:0.85em;'>"
            f"🛡️ DEFENDER DETECTED: {escape(severity)}"
            f"</div>"
            f"<div style='padding:0.5rem; background:#fff; border-top:1px solid {bg};'>"
            f"<div style='font-weight:bold; margin-bottom:0.2rem; color:#212529;'>{escape(rule_id)}</div>"
            f"<div style='font-size:0.9em; color:#212529;'>{escape(description)}</div>"
            f"</div>"
            f"</div>"
        )

    return f"<pre>{escape(str(data))}</pre>"


def _status_badge(status: str) -> str:
    """Helper to render a colored badge for action status."""
    s = str(status).upper()
    bg = "#6c757d"  # Default gray
    fg = "#fff"
    
    if s in ("COMPLETED", "EXECUTED", "SUCCESS"):
        bg = "#198754"  # Green
    elif s in ("FAILED", "REJECTED", "BLOCKED"):
        bg = "#dc3545"  # Red
    elif s == "RUNNING":
        bg = "#0d6efd"  # Blue
    elif s == "PENDING":
        bg = "#ffc107"  # Yellow
        fg = "#000"

    return (
        f"<span style='background-color:{bg}; color:{fg}; padding:0.2rem 0.4rem; "
        f"border-radius:4px; font-size:0.85em; font-weight:bold;'>{escape(s)}</span>"
    )


def _format_execution_output(task: Any) -> str:
    """Helper to format execution output from a task."""
    # Try common field names for result/output
    result = getattr(task, "result", None) or getattr(task, "output", None)

    if not result:
        return "<span class='muted'>-</span>"

    # If result is a JSON string, parse it
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except (json.JSONDecodeError, TypeError):
            pass

    if isinstance(result, dict):
        # If it has stdout/stderr structure (common in executors)
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")
        return_code = result.get("return_code")

        parts = []
        if return_code is not None and return_code != 0:
            parts.append(f"<div style='color:#dc3545; font-weight:bold; font-size:0.85em;'>Exit Code: {return_code}</div>")

        if stdout:
            parts.append(f"<div class='muted' style='font-size:0.8em;'>STDOUT:</div><pre style='max-height:150px; overflow:auto; font-size:0.85em;'>{escape(str(stdout))}</pre>")
        if stderr:
            parts.append(f"<div class='muted' style='font-size:0.8em;'>STDERR:</div><pre style='color:#dc3545; max-height:150px; overflow:auto; font-size:0.85em;'>{escape(str(stderr))}</pre>")

        if not parts:
            # Fallback for other dict content
            return f"<pre style='max-height:150px; overflow:auto; font-size:0.85em;'>{escape(json.dumps(result, indent=2))}</pre>"

        return "".join(parts)

    return f"<pre style='max-height:150px; overflow:auto; font-size:0.85em;'>{escape(str(result))}</pre>"


def _severity_badge(severity: str) -> str:
    """Helper to render a colored badge for alert severity."""
    s = str(severity).upper()
    bg_map = {
        "CRITICAL": "#842029",  # Dark Red
        "HIGH": "#dc3545",      # Red
        "MEDIUM": "#fd7e14",    # Orange
        "LOW": "#ffc107",       # Yellow
        "INFO": "#0dcaf0",      # Cyan
    }
    fg_map = {"CRITICAL": "#fff", "HIGH": "#fff", "MEDIUM": "#000", "LOW": "#000", "INFO": "#000"}

    bg = bg_map.get(s, "#6c757d")
    fg = fg_map.get(s, "#fff")

    return (
        f"<span style='background-color:{bg}; color:{fg}; padding:0.2rem 0.4rem; "
        f"border-radius:4px; font-size:0.85em; font-weight:bold;'>{escape(s)}</span>"
    )


def index(request: HttpRequest) -> HttpResponse:
    """List simulations (AttackState) with current phase and timestamps."""
    states = AttackState.objects.all().order_by("-updated_at")
    logger.debug("Rendering dashboard index with %s states", states.count())

    rows: list[str] = []
    for s in states:
        rows.append(
            "<tr>"
            f"<td><a href='attack/{s.pk}/'>{escape(s.name)}</a></td>"
            f"<td><code>{escape(s.current_phase)}</code></td>"
            f"<td>{escape(s.created_at.strftime('%Y-%m-%d %H:%M:%S'))}</td>"
            f"<td>{escape(s.updated_at.strftime('%Y-%m-%d %H:%M:%S'))}</td>"
            "</tr>"
        )

    body = (
        "<h1>XploitAI — Dashboard</h1>"
        "<p class='muted'>Phase 1 simulation dashboard (read-only visualization).</p>"
        "<h2>Simulations</h2>"
        "<table>"
        "<thead><tr><th>Name</th><th>Phase</th><th>Created</th><th>Updated</th></tr></thead>"
        f"<tbody>{''.join(rows) if rows else '<tr><td colspan=4 class=muted>No simulations.</td></tr>'}</tbody>"
        "</table>"
    )

    return HttpResponse(_html_page("XploitAI — Dashboard", body))


def attack_detail(request: HttpRequest, pk: int) -> HttpResponse:
    """Show details for a specific AttackState, including actions and timeline."""
    try:
        state = AttackState.objects.get(pk=pk)
    except AttackState.DoesNotExist as exc:
        logger.info("AttackState not found for pk=%s", pk)
        raise Http404("Simulation not found") from exc

    actions = Action.objects.filter(attack_state=state).order_by("created_at")
    events = AttackTimelineEvent.objects.filter(attack_state=state).order_by("created_at")
    tasks = ExecutionTask.objects.filter(action__attack_state=state).order_by("-created_at")
    alerts = DefenderAlert.objects.filter(attack_state=state).order_by("-created_at")

    # --- Autonomy Metrics Calculation ---
    consecutive_failures = 0
    # Check recent actions for failures (proxy for retry count)
    # We iterate the queryset in reverse (newest first)
    for a in actions.reverse():
        if a.status == 'FAILED':
            consecutive_failures += 1
        else:
            break

    # --- Autonomy Status Panel ---
    status_color = "#6c757d"  # Default Grey
    if state.autonomy_status == "RUNNING":
        status_color = "#198754"  # Green
    elif state.autonomy_status == "STOPPED":
        status_color = "#dc3545"  # Red
    elif state.autonomy_status == "PAUSED":
        status_color = "#ffc107"  # Yellow

    autonomy_panel = (
        "<div style='background:#f8f9fa; border:1px solid #dee2e6; border-radius:6px; padding:1rem; margin-bottom:1.5rem;'>"
        "<h3 style='margin-top:0;'>Autonomy Status</h3>"
        "<div style='display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:1rem;'>"
        f"<div><div class='muted'>State</div><div style='font-size:1.2rem; font-weight:bold; color:{status_color};'>{escape(state.get_autonomy_status_display())}</div></div>"
        f"<div><div class='muted'>Consecutive Failures</div><div style='font-size:1.2rem;'>{consecutive_failures}</div></div>"
    )

    if state.autonomy_status == "STOPPED":
        reason = state.stop_reason or "No reason provided"
        autonomy_panel += (
            f"<div style='grid-column: 1 / -1;'><div class='muted'>Stop Reason</div><div style='font-family:monospace; background:#fff; padding:0.5rem; border:1px solid #eee; border-radius:4px;'>{escape(reason)}</div></div>"
        )
    autonomy_panel += "</div></div>"

    # --- Interaction Visualization (Attacker vs Defender) ---
    # Combine Actions and Alerts into a single chronological stream to visualize interaction
    interaction_events = []
    for a in actions:
        interaction_events.append({'ts': a.created_at, 'type': 'ATTACKER', 'obj': a})
    for alert in alerts:
        interaction_events.append({'ts': alert.created_at, 'type': 'DEFENDER', 'obj': alert})
    
    # Sort by timestamp to show temporal flow
    interaction_events.sort(key=lambda x: x['ts'])

    interaction_rows = []
    for event in interaction_events:
        ts_str = event['ts'].strftime('%H:%M:%S')
        if event['type'] == 'ATTACKER':
            action = event['obj']
            # Attacker Cell (Left)
            attacker_html = (
                f"<div style='background:#f8f9fa; padding:0.6rem; border-radius:4px; border-left:4px solid #0d6efd; box-shadow: 0 1px 2px rgba(0,0,0,0.05);'>"
                f"<div style='font-weight:bold; color:#0d6efd; margin-bottom:0.2rem;'>{escape(action.name)}</div>"
                f"<div style='font-size:0.9em; color:#212529; margin-bottom:0.3rem;'>{escape(action.description or '')}</div>"
                f"<div>{_status_badge(action.status)}</div>"
                f"</div>"
            )
            defender_html = ""
        else:
            alert = event['obj']
            # Defender Cell (Right)
            attacker_html = ""
            defender_html = (
                f"<div style='background:#fff5f5; padding:0.6rem; border-radius:4px; border-left:4px solid #dc3545; box-shadow: 0 1px 2px rgba(0,0,0,0.05);'>"
                f"<div style='font-weight:bold; color:#dc3545; margin-bottom:0.2rem;'>🛡️ {escape(alert.rule_id)}</div>"
                f"<div style='font-size:0.9em; color:#212529; margin-bottom:0.3rem;'>{escape(alert.description)}</div>"
                f"<div>{_severity_badge(alert.severity)}</div>"
                f"</div>"
            )
        
        interaction_rows.append(
            "<tr>"
            f"<td class='muted' style='width:80px; vertical-align:top; padding-top:1rem; border:none;'>{ts_str}</td>"
            f"<td style='width:45%; vertical-align:top; padding:0.5rem; border:none;'>{attacker_html}</td>"
            f"<td style='width:45%; vertical-align:top; padding:0.5rem; border:none;'>{defender_html}</td>"
            "</tr>"
        )

    alert_rows: list[str] = []
    for alert in alerts:
        alert_rows.append(
            "<tr>"
            f"<td>{_severity_badge(alert.severity)}</td>"
            f"<td>{escape(alert.rule_id)}</td>"
            f"<td>{escape(alert.description)}</td>"
            f"<td class='muted'>{escape(alert.created_at.strftime('%Y-%m-%d %H:%M:%S'))}</td>"
            "</tr>"
        )

    task_rows: list[str] = []
    for t in tasks:
        cmd = getattr(t, "command", "") or ""
        # Render command in a scrollable block instead of truncating
        cmd_html = f"<pre style='max-height:80px; overflow:auto; white-space:pre-wrap; word-break:break-all; font-size:0.85em; margin:0;'>{escape(cmd)}</pre>"

        output_html = _format_execution_output(t)

        task_rows.append(
            "<tr>"
            f"<td>{t.id}</td>"
            f"<td>{escape(t.action_name)}</td>"
            f"<td>{_status_badge(t.status)}</td>"
            f"<td style='min-width:200px;'>{cmd_html}</td>"
            f"<td style='min-width:200px;'>{output_html}</td>"
            f"<td class='muted'>{escape(t.created_at.strftime('%H:%M:%S'))}</td>"
            f"<td class='muted'>{escape(t.updated_at.strftime('%H:%M:%S'))}</td>"
            "</tr>"
        )

    action_rows: list[str] = []
    for i, a in enumerate(actions, 1):
        mem_badge = _render_memory_badge(a.parameters)
        action_rows.append(
            "<tr>"
            f"<td><strong>{i}</strong></td>"
            f"<td>{escape(a.name)}</td>"
            f"<td class='muted'>{escape(a.description or '')}</td>"
            f"<td style='font-size:0.9em; color:#495057; max-width:300px;'>{escape(a.reasoning or '')}{mem_badge}</td>"
            f"<td>{_status_badge(a.status)}</td>"
            f"<td><pre>{escape(str(a.parameters))}</pre></td>"
            f"<td class='muted'>{escape(a.created_at.strftime('%Y-%m-%d %H:%M:%S'))}</td>"
            f"<td class='muted'>{escape(a.updated_at.strftime('%Y-%m-%d %H:%M:%S'))}</td>"
            "</tr>"
        )

    event_rows: list[str] = []
    for e in events:
        event_rows.append(
            "<tr>"
            f"<td><code>{escape(e.get_event_type_display())}</code></td>"
            f"<td><code>{escape(e.phase)}</code></td>"
            f"<td>{escape(e.created_at.strftime('%Y-%m-%d %H:%M:%S'))}</td>"
            f"<td class='muted'>{escape(e.message)}</td>"
            f"<td>{_format_event_data(e.data)}</td>"
            "</tr>"
        )

    body = (
        "<p><a href='../../'>← Back to simulations</a></p>"
        f"<h1>{escape(state.name)}</h1>"
        f"<p>Current phase: <code>{escape(state.current_phase)}</code></p>"
        f"{autonomy_panel}"
        "<h2>Attacker vs Defender Interaction</h2>"
        "<table style='border:none; margin-bottom:2rem;'>"
        f"<tbody>{''.join(interaction_rows) if interaction_rows else '<tr><td colspan=3 class=muted>No interactions recorded.</td></tr>'}</tbody>"
        "</table>"
        "<h2>Defender Alerts</h2>"
        "<table>"
        "<thead><tr><th>Severity</th><th>Rule ID</th><th>Description</th><th>Detected At</th></tr></thead>"
        f"<tbody>{''.join(alert_rows) if alert_rows else '<tr><td colspan=4 class=muted>No alerts detected.</td></tr>'}</tbody>"
        "</table>"
        "<h2>Execution Queue</h2>"
        "<table>"
        "<thead><tr><th>ID</th><th>Action</th><th>Status</th><th>Command</th><th>Output</th><th>Created</th><th>Updated</th></tr></thead>"
        f"<tbody>{''.join(task_rows) if task_rows else '<tr><td colspan=7 class=muted>No execution tasks.</td></tr>'}</tbody>"
        "</table>"
        "<h2>Execution Plan</h2>"
        "<table>"
        "<thead><tr><th>Step</th><th>Name</th><th>Description</th><th>Reasoning</th><th>Status</th><th>Parameters</th><th>Created</th><th>Updated</th></tr></thead>"
        f"<tbody>{''.join(action_rows) if action_rows else '<tr><td colspan=8 class=muted>No actions.</td></tr>'}</tbody>"
        "</table>"
        "<h2>Timeline</h2>"
        "<table>"
        "<thead><tr><th>Type</th><th>Phase</th><th>At</th><th>Message</th><th>Data</th></tr></thead>"
        f"<tbody>{''.join(event_rows) if event_rows else '<tr><td colspan=5 class=muted>No events.</td></tr>'}</tbody>"
        "</table>"
    )

    return HttpResponse(_html_page(f"XploitAI — {state.name}", body))


urlpatterns = [
    path("", index, name="dashboard_index"),
    path("attack/<int:pk>/", attack_detail, name="dashboard_attack_detail"),
]
