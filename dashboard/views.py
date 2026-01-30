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

import logging
from typing import Iterable

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
            f"<td><code>{escape(a.status)}</code></td>"
            f"<td><pre>{escape(str(a.parameters))}</pre></td>"
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
            f"<td><pre>{escape(str(e.data))}</pre></td>"
            "</tr>"
        )

    body = (
        "<p><a href='../../'>← Back to simulations</a></p>"
        f"<h1>{escape(state.name)}</h1>"
        f"<p>Current phase: <code>{escape(state.current_phase)}</code></p>"
        "<h2>Actions</h2>"
        "<table>"
        "<thead><tr><th>Name</th><th>Description</th><th>Status</th><th>Parameters</th></tr></thead>"
        f"<tbody>{''.join(action_rows) if action_rows else '<tr><td colspan=4 class=muted>No actions.</td></tr>'}</tbody>"
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
