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

from core.models import AttackState, Action, AttackTimelineEvent

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
            rows.append(
                f"<tr><td>{i}</td><td>{escape(str(action))}</td><td>{escape(str(reason))}</td></tr>"
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
    if s == "COMPLETED":
        bg = "#198754"  # Green
    elif s == "FAILED":
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

    action_rows: list[str] = []
    for a in actions:
        action_rows.append(
            "<tr>"
            f"<td>{escape(a.name)}</td>"
            f"<td class='muted'>{escape(a.description or '')}</td>"
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
        "<h2>Actions</h2>"
        "<table>"
        "<thead><tr><th>Name</th><th>Description</th><th>Status</th><th>Parameters</th><th>Created</th><th>Updated</th></tr></thead>"
        f"<tbody>{''.join(action_rows) if action_rows else '<tr><td colspan=6 class=muted>No actions.</td></tr>'}</tbody>"
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
