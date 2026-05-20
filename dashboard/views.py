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
import uuid
from copy import deepcopy
from datetime import timedelta
from pathlib import Path
from typing import Any

from django.shortcuts import render, get_object_or_404, redirect
from . import auth
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse
from django.views.decorators.http import require_POST
from django.views.decorators.cache import never_cache
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django.core.serializers.json import DjangoJSONEncoder
from django.urls import reverse
from django.db.models import Q

from core.models import AttackState, Action, AttackTimelineEvent, ExecutionTask, DefenderAlert, AttackerExecutor, AttackTarget, AttackContext, Command, ExecutionResult
from ai.command_generator import CommandGenerator
from ai.agentic_architecture import (
    AGENTIC_ARCHITECTURE_VERSION,
    build_agentic_architecture_snapshot,
)
from executor import ssh_executor
from services.execution_service import ExecutionService
from services.remote_execution_service import RemoteExecutionService
from services.ssh_execution_service import SSHExecutionService
from services.reporting_service import AttackReportService
from services.quick_test_service import QuickTestService, quick_action_catalog, selected_quick_actions
from services.tool_preflight import TOOL_PREFLIGHT_STATE_KEY, build_tool_preflight_state
from services.command_template_utils import (
    build_target_context,
    infer_required_tools,
    is_probable_shell_command,
    normalize_command_targets,
    normalize_command_template,
    render_command_template,
    uses_disallowed_tool,
)
from parser.output_parser import merge_findings, parse_output
from core.config import get_config, set_config
from core.levels import (
    DEFAULT_LEVEL_LIMITS,
    build_runtime_profile,
    canonical_kill_chain_label,
    dashboard_phase_catalog,
    dashboard_phase_display_name,
    dashboard_phase_index,
    dashboard_phase_key,
    dashboard_phase_meta,
    is_valid_dashboard_phase,
    next_dashboard_phase,
    normalize_phase_name,
    pentest_stage_label,
    previous_dashboard_phase,
)
from ai.llm.groq_adapter import GroqAdapter
from state.state_manager import StateManager

logger = logging.getLogger(__name__)
EXECUTOR_HEARTBEAT_THRESHOLD_SECONDS = 30


def _delete_attack_runtime_state_file(state_id: int) -> None:
    try:
        path = Path(StateManager(state_id).json_store.path)
        if path.exists() and path.is_file():
            path.unlink()
    except Exception as exc:
        logger.warning("Unable to remove runtime state file for AttackState %s: %s", state_id, exc)


def _delete_attack_states(states) -> int:
    state_ids = list(states.values_list("id", flat=True))
    if not state_ids:
        return 0

    action_ids = list(Action.objects.filter(attack_state_id__in=state_ids).values_list("id", flat=True))
    if action_ids:
        ExecutionTask.objects.filter(action_id__in=action_ids).delete()

    for state_id in state_ids:
        _delete_attack_runtime_state_file(state_id)

    deleted_count = len(state_ids)
    AttackState.objects.filter(id__in=state_ids).delete()
    return deleted_count


def _clean_idempotency_key(value: str | None) -> str:
    key = str(value or "").strip()
    if not key:
        return ""
    return key[:120]


def _idempotent_attack_for_request(request: HttpRequest, scope: str) -> AttackState | None:
    key = _clean_idempotency_key(request.POST.get("idempotency_key"))
    if not key:
        return None
    return (
        AttackState.objects.filter(
            owner=request.user,
            state_data__idempotency_key=key,
            state_data__idempotency_scope=scope,
        )
        .order_by("-created_at")
        .first()
    )


def _store_idempotency(state: AttackState, key: str, scope: str) -> None:
    if not key:
        return
    state_data = state.state_data if isinstance(state.state_data, dict) else {}
    state_data["idempotency_key"] = key
    state_data["idempotency_scope"] = scope
    state.state_data = state_data


def _is_waiting_for_plan_approval(state: AttackState | None) -> bool:
    if not state:
        return False
    state_data = state.state_data if isinstance(state.state_data, dict) else {}
    if state_data.get("plan_rejected"):
        return False
    if state_data.get("run_type") == "quick_test":
        return False
    plan = state.current_plan if isinstance(state.current_plan, dict) else {}
    if plan.get("scope") == "quick_test":
        return False
    steps = plan.get("steps") if isinstance(plan.get("steps"), list) else []
    return bool(steps) and not bool(state_data.get("plan_approved", False))


def _normalize_phase_key(value: Any) -> str:
    return dashboard_phase_key(value)


def _display_phase_name(value: Any) -> str:
    mapped = dashboard_phase_display_name(value)
    if mapped != "Unknown Phase":
        return mapped
    text = str(value or "").strip()
    if not text:
        return "Unknown Phase"
    return text.replace("_", " ").title()


def _phase_badge_status(state: AttackState, phase_key: str, phase_payload: dict[str, Any] | None = None) -> str:
    payload = phase_payload or {}
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    if phase_key == "completed":
        return "completed" if (state.state_data or {}).get("report_artifacts") else "pending"
    if payload.get("is_current"):
        if state.autonomy_status in {"RUNNING", "PLANNING"}:
            return "running"
        if summary.get("failed"):
            return "failed"
        if summary.get("total") and summary.get("completed") == summary.get("total"):
            return "completed"
    if payload.get("source") == "review":
        return "completed"
    return "pending"


def _phase_filter_match(event_phase: Any, phase_key: str) -> bool:
    return _normalize_phase_key(event_phase) == _normalize_phase_key(phase_key)


def _summarize_findings(findings: Any) -> list[dict[str, Any]]:
    if isinstance(findings, dict):
        return [
            {"key": str(key), "value": value}
            for key, value in findings.items()
        ]
    if isinstance(findings, list):
        return [
            {"key": f"Finding {idx + 1}", "value": value}
            for idx, value in enumerate(findings)
        ]
    if findings:
        return [{"key": "Finding", "value": findings}]
    return []


def _enrich_result_findings_from_stdout(result: Any) -> None:
    findings = result.findings if isinstance(getattr(result, "findings", None), dict) else {}
    stdout = getattr(result, "stdout", "") or ""
    if findings.get("valid_credentials") or "AUTH_SUCCESS:" not in stdout and "SUCCESSFUL_CREDENTIAL:" not in stdout:
        return
    parsed = parse_output("ExploitAttempt", stdout)
    if not parsed.get("valid_credentials"):
        return
    result.findings = merge_findings(findings, parsed)
    try:
        result.save(update_fields=["findings"])
    except Exception:
        logger.warning("Unable to persist enriched credential findings for result %s", getattr(result, "id", "unknown"))


def _status_from_result(value: Any) -> str:
    status = str(value or "").upper()
    if status in {"SUCCESS", "COMPLETED", "EXECUTED"}:
        return "completed"
    if status in {"FAILED", "ERROR", "REJECTED"}:
        return "failed"
    if status in {"RUNNING"}:
        return "running"
    return "pending"


def _step_summary(steps: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "total": len(steps),
        "completed": sum(1 for step in steps if step.get("status") == "completed"),
        "failed": sum(1 for step in steps if step.get("status") == "failed"),
        "running": sum(1 for step in steps if step.get("status") == "running"),
        "pending": sum(1 for step in steps if step.get("status") == "pending"),
        "attempts": sum(int(step.get("attempt_count") or 0) for step in steps),
        "alternatives": sum(1 for step in steps if step.get("alternative_pending")),
    }


def _latest_step_attempt(step: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(step, dict):
        return {}
    history = step.get("execution_history")
    if not isinstance(history, list) or not history:
        return {}
    latest = history[-1]
    return latest if isinstance(latest, dict) else {}


def _build_attack_run_history(state: AttackState) -> dict[str, Any]:
    state_data = state.state_data or {}
    phase_reviews = state_data.get("level_history") or state_data.get("phase_reviews", [])
    phases: list[dict[str, Any]] = []
    reviewed_phase_keys: set[str] = set()

    for index, review in enumerate(phase_reviews, start=1):
        details = review.get("details") if isinstance(review, dict) else {}
        details = details if isinstance(details, dict) else {}
        review_phase = review.get("phase") if isinstance(review, dict) else None
        plan_snapshot = details.get("plan_snapshot") or review.get("plan_snapshot") or []
        result_snapshot = details.get("results_snapshot") or review.get("results_snapshot") or []
        latest_result_by_command = {
            item.get("command"): item
            for item in result_snapshot
            if isinstance(item, dict) and item.get("command")
        }

        steps = []
        for step_index, step in enumerate(plan_snapshot, start=1):
            item = deepcopy(step)
            action_name = item.get("action_type") or item.get("action") or ""
            matched_result = latest_result_by_command.get(action_name, {})
            item["status"] = item.get("status") or _status_from_result(matched_result.get("status") or "SUCCESS")
            item.setdefault("step_number", step_index)
            if matched_result.get("stdout_excerpt") and not item.get("output_excerpt"):
                item["output_excerpt"] = matched_result.get("stdout_excerpt")
            elif matched_result.get("stderr_excerpt") and not item.get("output_excerpt"):
                item["output_excerpt"] = matched_result.get("stderr_excerpt")
            steps.append(item)

        findings = (
            details.get("current_findings")
            or review.get("findings")
            or {key: True for key in details.get("key_evidence", [])}
        )
        outputs = []
        for item in result_snapshot:
            if not isinstance(item, dict):
                continue
            outputs.append(
                {
                    "command": item.get("command") or "unknown",
                    "status": item.get("status") or "PLANNED",
                    "stdout_excerpt": item.get("stdout_excerpt") or "",
                    "stderr_excerpt": item.get("stderr_excerpt") or "",
                    "findings": item.get("findings") or {},
                }
            )

        phase_key = _normalize_phase_key(review_phase)
        if phase_key:
            reviewed_phase_keys.add(phase_key)

        phases.append(
            {
                "phase": review_phase or f"Phase {index}",
                "phase_display": _display_phase_name(review_phase or f"Phase {index}"),
                "level": review.get("level") if isinstance(review, dict) else {},
                "kill_chain_label": ((review.get("level") or {}).get("kill_chain_label") if isinstance(review, dict) else "") or canonical_kill_chain_label(review_phase),
                "stage_label": pentest_stage_label(review_phase),
                "next_phase": review.get("next_phase") if isinstance(review, dict) else "",
                "review": review.get("review", "") if isinstance(review, dict) else "",
                "details": details,
                "steps": steps,
                "summary": _step_summary(steps),
                "findings": _summarize_findings(findings),
                "outputs": outputs,
                "source": "review",
            }
        )

    active_plan_view = _build_plan_view_state(state)
    active_phase = (state.current_plan or {}).get("phase") or state.current_phase
    active_phase_key = _normalize_phase_key(active_phase)
    active_step_names = [
        step.get("action_type") or step.get("action")
        for step in (state.current_plan or {}).get("steps") or []
    ]
    latest_reviewed_steps = []
    for phase in reversed(phases):
        if _normalize_phase_key(phase.get("phase")) == active_phase_key:
            latest_reviewed_steps = [
                step.get("action_type") or step.get("action")
                for step in phase.get("steps", [])
            ]
            break
    should_append_active_phase = bool(active_plan_view.get("steps")) and (
        active_phase_key not in reviewed_phase_keys
        or active_step_names != latest_reviewed_steps
    )

    if should_append_active_phase:
        current_level = (state.current_plan or {}).get("level") if isinstance((state.current_plan or {}).get("level"), dict) else {}
        phases.append(
            {
                "phase": active_phase,
                "phase_display": _display_phase_name(active_phase),
                "level": current_level,
                "kill_chain_label": current_level.get("kill_chain_label") or canonical_kill_chain_label(active_phase),
                "stage_label": pentest_stage_label(active_phase),
                "next_phase": "",
                "review": "",
                "details": {},
                "steps": deepcopy(active_plan_view.get("steps") or []),
                "summary": deepcopy(active_plan_view.get("summary") or _step_summary([])),
                "findings": _summarize_findings(state_data.get("findings") or {}),
                "outputs": [
                    {
                        "command": history_item.get("command") or step.get("action_type") or step.get("action") or "unknown",
                        "status": history_item.get("status") or ("SUCCESS" if step.get("status") == "completed" else "FAILED"),
                        "stdout_excerpt": history_item.get("stdout_excerpt") or "",
                        "stderr_excerpt": history_item.get("stderr_excerpt") or "",
                        "findings": history_item.get("findings") or step.get("last_findings") or {},
                    }
                    for step in (active_plan_view.get("steps") or [])
                    for history_item in (step.get("execution_history") or [])
                ],
                "source": "active_plan",
            }
        )

    aggregate_steps = [step for phase in phases for step in phase.get("steps", [])]
    summary = _step_summary(aggregate_steps)
    summary["phases"] = len(phases)
    summary["findings"] = sum(len(phase.get("findings", [])) for phase in phases)
    summary["outputs"] = sum(len(phase.get("outputs", [])) for phase in phases)

    return {
        "phases": phases,
        "summary": summary,
    }


def _build_plan_view_state(state: AttackState) -> dict[str, Any]:
    """
    Build a UI-friendly, execution-aware representation of current_plan.
    Adds per-step status and summary counters for staged execution UX.
    """
    plan = deepcopy(state.current_plan or {})
    raw_steps = plan.get("steps") or []

    state_data = state.state_data or {}
    script_artifacts = state_data.get("script_artifacts")
    if not isinstance(script_artifacts, list):
        script_artifacts = []
    script_artifacts_by_id = {
        str(artifact.get("id")): artifact
        for artifact in script_artifacts
        if isinstance(artifact, dict) and artifact.get("id")
    }
    report_artifacts = state_data.get("report_artifacts")
    if not isinstance(report_artifacts, list):
        report_artifacts = []

    if not raw_steps:
        return {
            "rationale": plan.get("rationale", ""),
            "steps": [],
            "summary": {
                "total": 0,
                "completed": 0,
                "failed": 0,
                "running": 0,
                "pending": 0,
                "attempts": 0,
                "alternatives": 0,
            },
            "current_step": None,
            "all_done": False,
            "level": plan.get("level") or {},
            "limits": plan.get("limits") or {},
            "runtime": plan.get("runtime") or {},
            "phase_reviews": (state.state_data or {}).get("level_history") or (state.state_data or {}).get("phase_reviews", []),
            "level_history": (state.state_data or {}).get("level_history") or (state.state_data or {}).get("phase_reviews", []),
            "phase_transition_pending": (state.state_data or {}).get("phase_transition_pending") or (state.state_data or {}).get("level_transition_pending"),
            "level_transition_pending": (state.state_data or {}).get("level_transition_pending") or (state.state_data or {}).get("phase_transition_pending"),
            "script_artifacts": script_artifacts,
            "report_artifacts": report_artifacts,
            "last_report": report_artifacts[-1] if report_artifacts else None,
        }

    results = (
        state.execution_results
        .select_related("command")
        .order_by("-created_at")
    )
    command_lookup = {
        command.name: command
        for command in Command.objects.all()
    }
    llm_provider = ((state.state_data or {}).get("llm_provider") or "auto").lower()
    preview_generator = CommandGenerator(use_llm=False, llm_provider=llm_provider)
    target_context = build_target_context(
        (state.state_data or {}).get("target")
        or (state.state_data or {}).get("planner_context", {}).get("targets", [{}])[0].get("primary_ref", "")
    )

    latest_by_command: dict[str, Any] = {}
    for result in results:
        command_name = getattr(result.command, "name", None)
        if command_name and command_name not in latest_by_command:
            latest_by_command[command_name] = result

    steps = []
    for idx, step in enumerate(raw_steps):
        item = deepcopy(step)
        action_name = item.get("action_type") or item.get("action") or ""
        latest_attempt = _latest_step_attempt(item)
        match = latest_by_command.get(action_name)

        if item.get("status") == "completed":
            item["status"] = "completed"
        elif item.get("status") == "failed":
            item["status"] = "failed"
        elif item.get("status") == "running":
            item["status"] = "running"
        elif latest_attempt.get("status") == "SUCCESS":
            item["status"] = "completed"
        elif latest_attempt.get("status") in {"FAILED", "RETRY_SCHEDULED"}:
            item["status"] = "failed" if latest_attempt.get("status") == "FAILED" else "pending"
        elif match and match.status == "SUCCESS":
            item["status"] = "completed"
        elif match and match.status == "FAILED":
            item["status"] = "failed"
        else:
            item["status"] = "pending"

        command_obj = command_lookup.get(action_name)
        if command_obj:
            try:
                step_context = {**target_context, **(item.get("parameters") or {})}
                actual_command = item.get("resolved_command") or latest_attempt.get("command")
                if actual_command and is_probable_shell_command(actual_command):
                    item["command_preview"] = actual_command
                    item["command_preview_source"] = "executor"
                else:
                    generated_preview = preview_generator.generate(
                        action_name,
                        step_context,
                    ).shell_command
                    item["command_preview"] = generated_preview
                    item["command_preview"] = normalize_command_targets(item["command_preview"], step_context)
                    item["command_preview_source"] = "rule_based"
            except Exception:
                item["command_preview"] = command_obj.command_template or ""
                item["command_preview_source"] = "stored"
            item["required_tools"] = item.get("resolved_tools") or infer_required_tools(item.get("command_preview") or command_obj.command_template or "")
        else:
            item["command_preview"] = ""
            item["command_preview_source"] = ""
            item["required_tools"] = []

        item.setdefault("step_number", idx + 1)
        item.setdefault("attempt_count", len(item.get("execution_history") or []))
        item.setdefault("command_retry_count", 0)
        item.setdefault("max_retries", 2)
        item.setdefault("retry_cooldown_seconds", 2)
        item.setdefault("next_allowed_at", 0)
        item.setdefault("stage_label", pentest_stage_label(plan.get("phase") or state.current_phase))
        item.setdefault("execution_type", "command")
        item.setdefault("success_criteria", "")
        if item.get("execution_type") == "script":
            artifact_refs = item.get("artifact_refs") if isinstance(item.get("artifact_refs"), list) else []
            linked_artifacts = []
            for ref in artifact_refs:
                if not isinstance(ref, dict):
                    continue
                artifact_id = str(ref.get("id") or "")
                if artifact_id and artifact_id in script_artifacts_by_id:
                    linked_artifacts.append(script_artifacts_by_id[artifact_id])
            item["linked_script_artifacts"] = linked_artifacts
        item["cooldown_pending"] = (
            float(item.get("next_allowed_at") or 0) > timezone.now().timestamp()
            and item.get("status") in {"pending", "running"}
        )
        if not item.get("output_excerpt"):
            item["output_excerpt"] = (
                latest_attempt.get("stdout_excerpt")
                or latest_attempt.get("stderr_excerpt")
                or item.get("last_output_excerpt")
                or item.get("last_error_excerpt")
                or ""
            )
        steps.append(item)

    # Mark a single active step when attack is running/planning.
    unresolved_idx = next(
        (i for i, s in enumerate(steps) if s["status"] in ("pending", "failed", "running")),
        None,
    )
    if unresolved_idx is not None and state.autonomy_status in ("RUNNING", "PLANNING"):
        if steps[unresolved_idx]["status"] in ("pending", "failed"):
            steps[unresolved_idx]["status"] = "running"

    completed_count = sum(1 for s in steps if s["status"] == "completed")
    failed_count = sum(1 for s in steps if s["status"] == "failed")
    running_count = sum(1 for s in steps if s["status"] == "running")
    pending_count = sum(1 for s in steps if s["status"] == "pending")
    current_step = next((s for s in steps if s["status"] == "running"), None)

    return {
        "rationale": plan.get("rationale", ""),
        "level": plan.get("level") or {
            "phase_name": normalize_phase_name(plan.get("phase") or state.current_phase),
            "kill_chain_label": canonical_kill_chain_label(plan.get("phase") or state.current_phase),
        },
        "stage_label": plan.get("stage_label") or pentest_stage_label(plan.get("phase") or state.current_phase),
        "limits": plan.get("limits") or {},
        "runtime": plan.get("runtime") or {},
        "steps": steps,
        "summary": {
            "total": len(steps),
            "completed": completed_count,
            "failed": failed_count,
            "running": running_count,
            "pending": pending_count,
            "attempts": sum(int(s.get("attempt_count") or 0) for s in steps),
            "alternatives": sum(1 for s in steps if s.get("alternative_pending")),
        },
        "current_step": current_step,
        "all_done": completed_count == len(steps),
        "phase_reviews": (state.state_data or {}).get("level_history") or (state.state_data or {}).get("phase_reviews", []),
        "level_history": (state.state_data or {}).get("level_history") or (state.state_data or {}).get("phase_reviews", []),
        "phase_transition_pending": (state.state_data or {}).get("phase_transition_pending") or (state.state_data or {}).get("level_transition_pending"),
        "level_transition_pending": (state.state_data or {}).get("level_transition_pending") or (state.state_data or {}).get("phase_transition_pending"),
        "script_artifacts": script_artifacts,
        "report_artifacts": report_artifacts,
        "last_report": report_artifacts[-1] if report_artifacts else None,
    }


def _is_failed_stop_reason(stop_reason: str) -> bool:
    reason = str(stop_reason or "").lower()
    if not reason:
        return False
    failure_tokens = ("failed", "failure", "error", "halt", "stopped")
    safe_tokens = ("waiting for approval", "plan completed", "resuming execution")
    return any(token in reason for token in failure_tokens) and not any(token in reason for token in safe_tokens)


def _build_phase_cards(state: AttackState | None) -> dict[str, Any]:
    catalog = dashboard_phase_catalog()
    if not state:
        return {
            "cards": [
                {
                    **phase,
                    "phase_key": phase["key"],
                    "status": "pending",
                    "is_current": False,
                    "is_started": False,
                    "is_skipped_by_start": False,
                    "summary": {"total": 0, "completed": 0, "failed": 0, "running": 0, "pending": 0, "attempts": 0, "alternatives": 0},
                    "review": "",
                    "findings_count": 0,
                    "outputs_count": 0,
                    "detail_url": "",
                }
                for phase in catalog
            ],
            "aggregate": {"completed": 0, "running": 0, "failed": 0, "pending": len(catalog), "selected_run": None},
        }

    history = _build_attack_run_history(state)
    start_phase = _normalize_phase_key((state.state_data or {}).get("start_phase") or state.current_phase)
    start_phase_idx = dashboard_phase_index(start_phase)
    current_phase_key = _normalize_phase_key((state.current_plan or {}).get("phase") or state.current_phase)
    completed_phase_keys = _completed_phase_keys_for_state(state)
    phases_by_key = {
        _normalize_phase_key(item.get("phase")): item
        for item in history.get("phases", [])
        if _normalize_phase_key(item.get("phase"))
    }

    cards: list[dict[str, Any]] = []
    for phase in catalog:
        phase_key = phase["key"]
        payload = phases_by_key.get(phase_key, {})
        summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else _step_summary([])
        is_current = phase_key == current_phase_key
        is_started = bool(payload) or is_current
        is_skipped_by_start = start_phase_idx > -1 and dashboard_phase_index(phase_key) < start_phase_idx
        status = _phase_badge_status(state, phase_key, {**payload, "summary": summary, "is_current": is_current})
        if phase_key in completed_phase_keys and not is_current:
            status = "completed"
        if phase_key == "completed" and state.autonomy_status == "STOPPED" and "plan completed" in str(state.stop_reason or "").lower():
            status = "completed"
        if is_current and state.autonomy_status == "STOPPED" and summary.get("failed") and _is_failed_stop_reason(state.stop_reason):
            status = "failed"
        cards.append(
            {
                **phase,
                "phase_key": phase_key,
                "display_name": phase["display_name"],
                "status": status,
                "is_current": is_current,
                "is_started": is_started,
                "is_skipped_by_start": is_skipped_by_start,
                "summary": summary,
                "review": payload.get("review", ""),
                "findings_count": len(payload.get("findings", [])),
                "outputs_count": len(payload.get("outputs", [])),
                "detail_url": reverse("dashboard_attack_phase_detail", kwargs={"pk": state.pk, "phase_key": phase_key}),
                "source": payload.get("source", ""),
            }
        )

    aggregate = {
        "completed": sum(1 for card in cards if card["status"] == "completed"),
        "running": sum(1 for card in cards if card["status"] == "running"),
        "failed": sum(1 for card in cards if card["status"] == "failed"),
        "pending": sum(1 for card in cards if card["status"] == "pending"),
        "selected_run": state,
    }
    return {"cards": cards, "aggregate": aggregate}


def _build_phase_detail_payload(state: AttackState, phase_key: str) -> dict[str, Any]:
    normalized_phase = _normalize_phase_key(phase_key)
    if not is_valid_dashboard_phase(normalized_phase):
        raise Http404("Unknown phase")

    history = _build_attack_run_history(state)
    selected = next(
        (item for item in history.get("phases", []) if _normalize_phase_key(item.get("phase")) == normalized_phase),
        None,
    )
    plan_view = _build_plan_view_state(state)
    start_phase = _normalize_phase_key((state.state_data or {}).get("start_phase") or state.current_phase)
    start_phase_idx = dashboard_phase_index(start_phase)
    phase_idx = dashboard_phase_index(normalized_phase)
    is_current = normalized_phase == _normalize_phase_key((state.current_plan or {}).get("phase") or state.current_phase)
    if normalized_phase == "completed":
        selected = {
            "phase": "completed",
            "phase_display": dashboard_phase_display_name("completed"),
            "summary": {
                "total": history.get("summary", {}).get("total", 0),
                "completed": history.get("summary", {}).get("completed", 0),
                "failed": history.get("summary", {}).get("failed", 0),
                "running": history.get("summary", {}).get("running", 0),
                "pending": history.get("summary", {}).get("pending", 0),
                "attempts": history.get("summary", {}).get("attempts", 0),
                "alternatives": history.get("summary", {}).get("alternatives", 0),
            },
            "review": state.stop_reason or "",
            "details": {"summary": state.stop_reason or ""},
            "findings": [],
            "outputs": [],
            "steps": [],
            "source": "synthetic",
        }

    selected = selected or {
        "phase": normalized_phase,
        "phase_display": dashboard_phase_display_name(normalized_phase),
        "summary": _step_summary([]),
        "review": "",
        "details": {},
        "findings": [],
        "outputs": [],
        "steps": [],
        "source": "",
    }
    selected["status"] = _phase_badge_status(state, normalized_phase, {"summary": selected.get("summary", {}), "is_current": is_current, "source": selected.get("source")})
    if normalized_phase in _completed_phase_keys_for_state(state) and not is_current:
        selected["status"] = "completed"
    if is_current and state.autonomy_status == "STOPPED" and selected.get("summary", {}).get("failed") and _is_failed_stop_reason(state.stop_reason):
        selected["status"] = "failed"
    selected["is_current"] = is_current
    selected["is_started"] = bool(selected.get("source")) or is_current or normalized_phase == "completed"
    selected["is_skipped_by_start"] = start_phase_idx > -1 and phase_idx > -1 and phase_idx < start_phase_idx
    selected["findings_count"] = len(selected.get("findings", []))
    selected["outputs_count"] = len(selected.get("outputs", []))
    selected["previous_phase"] = previous_dashboard_phase(normalized_phase)
    selected["next_phase"] = next_dashboard_phase(normalized_phase)
    selected["empty_state"] = not any([selected.get("steps"), selected.get("outputs"), selected.get("review"), selected.get("findings")]) and not normalized_phase == "completed"
    selected["meta"] = dashboard_phase_meta(normalized_phase) or {"display_name": _display_phase_name(normalized_phase), "description": ""}
    selected["plan_view"] = plan_view if is_current else {}
    selected["timeline"] = [
        event for event in _get_unified_events(state)
        if _phase_filter_match((event.get("data") or {}).get("phase"), normalized_phase)
    ]
    selected["report_artifacts"] = plan_view.get("report_artifacts", [])
    selected["latest_report"] = plan_view.get("last_report")
    return selected


def _completed_phase_keys_for_state(state: AttackState) -> set[str]:
    state_data = state.state_data if isinstance(state.state_data, dict) else {}
    history = state_data.get("level_history") or state_data.get("phase_reviews") or []
    completed: set[str] = set()
    if isinstance(history, list):
        for item in history:
            if not isinstance(item, dict):
                continue
            phase_key = _normalize_phase_key(item.get("phase"))
            if phase_key:
                completed.add(phase_key)
    current_plan = state.current_plan if isinstance(state.current_plan, dict) else {}
    current_phase_key = _normalize_phase_key(current_plan.get("phase") or state.current_phase)
    current_steps = current_plan.get("steps") if isinstance(current_plan.get("steps"), list) else []
    if current_phase_key and current_steps:
        statuses = [str(step.get("status") or "").lower() for step in current_steps if isinstance(step, dict)]
        if statuses and all(status == "completed" for status in statuses):
            completed.add(current_phase_key)
    return completed


def _resolve_restart_phase(state: AttackState, requested_phase: str) -> str:
    ordered_phases = [
        item["normalized_key"]
        for item in dashboard_phase_catalog(executable_only=True)
        if item.get("normalized_key")
    ]
    normalized_requested = _normalize_phase_key(requested_phase)
    if normalized_requested not in ordered_phases:
        normalized_requested = "reconnaissance"

    return normalized_requested


def _prune_completed_commands_for_restart(completed_commands: list[Any], restart_phase: str) -> list[int]:
    if not completed_commands:
        return []
    phase_order = {
        item["normalized_key"]: index
        for index, item in enumerate(dashboard_phase_catalog(executable_only=True))
        if item.get("normalized_key")
    }
    restart_index = phase_order.get(_normalize_phase_key(restart_phase), 0)
    commands = {
        command.id: command
        for command in Command.objects.select_related("phase").filter(id__in=completed_commands)
    }
    retained: list[int] = []
    for command_id in completed_commands:
        command = commands.get(command_id)
        if not command:
            continue
        command_phase_index = phase_order.get(_normalize_phase_key(getattr(command.phase, "name", "")), restart_index)
        if command_phase_index < restart_index:
            retained.append(command_id)
    return retained


def _refresh_step_command(step: dict[str, Any], state: AttackState) -> None:
    action_name = step.get("action_type") or step.get("action") or ""
    if not action_name:
        return
    target_context = build_target_context(
        (state.state_data or {}).get("target")
        or (state.state_data or {}).get("planner_context", {}).get("targets", [{}])[0].get("primary_ref", "")
    )
    parameters = {**target_context, **(step.get("parameters") or {})}
    generated = CommandGenerator(use_llm=False, llm_provider="auto").generate(action_name, parameters)
    command = normalize_command_targets(generated.shell_command, parameters)
    if uses_disallowed_tool(command):
        command = "echo 'BLOCKED_TOOL: arjun is disabled; regenerate this phase plan for an alternative parameter probe'; exit 2"
    step["resolved_command"] = command
    step["resolved_tools"] = infer_required_tools(command)


def _preserve_current_plan_history(state: AttackState) -> bool:
    plan = state.current_plan if isinstance(state.current_plan, dict) else {}
    steps = deepcopy(plan.get("steps") or [])
    if not steps:
        return False

    has_execution_evidence = any(
        step.get("execution_history")
        or step.get("last_output_excerpt")
        or step.get("last_error_excerpt")
        or str(step.get("status") or "").lower() in {"completed", "failed", "running"}
        for step in steps
        if isinstance(step, dict)
    )
    if not has_execution_evidence:
        return False

    phase_name = plan.get("phase") or state.current_phase
    state_data = state.state_data if isinstance(state.state_data, dict) else {}
    history = list(state_data.get("level_history") or state_data.get("phase_reviews") or [])
    last_entry = history[-1] if history and isinstance(history[-1], dict) else {}
    last_details = last_entry.get("details") if isinstance(last_entry.get("details"), dict) else {}
    last_snapshot = last_details.get("plan_snapshot") or last_entry.get("plan_snapshot") or []
    if _normalize_phase_key(last_entry.get("phase")) == _normalize_phase_key(phase_name) and last_snapshot == steps:
        return False

    results_snapshot: list[dict[str, Any]] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        attempts = step.get("execution_history") if isinstance(step.get("execution_history"), list) else []
        latest_attempt = attempts[-1] if attempts and isinstance(attempts[-1], dict) else {}
        result_status = (
            latest_attempt.get("status")
            or ("SUCCESS" if str(step.get("status") or "").lower() == "completed" else "FAILED" if str(step.get("status") or "").lower() == "failed" else "PLANNED")
        )
        results_snapshot.append(
            {
                "command": step.get("action_type") or step.get("action") or "unknown",
                "status": result_status,
                "stdout_excerpt": latest_attempt.get("stdout_excerpt") or step.get("last_output_excerpt") or "",
                "stderr_excerpt": latest_attempt.get("stderr_excerpt") or step.get("last_error_excerpt") or "",
                "findings": latest_attempt.get("findings") or step.get("last_findings") or {},
                "resolved_command": step.get("resolved_command") or latest_attempt.get("command") or "",
            }
        )

    findings = deepcopy(state_data.get("findings") or {})
    review_entry = {
        "phase": phase_name,
        "level": deepcopy(plan.get("level") or {}),
        "next_phase": next_dashboard_phase(phase_name) or "",
        "review": state.stop_reason or f"Preserved {phase_name} plan state before restart.",
        "findings": findings,
        "details": {
            "current_findings": findings,
            "plan_snapshot": steps,
            "results_snapshot": results_snapshot,
        },
    }
    history.append(review_entry)
    state_data["level_history"] = history
    state_data["phase_reviews"] = history
    state.state_data = state_data
    return True


def _launch_assessment(state: AttackState) -> None:
    """Start the appropriate assessment service for the state's execution mode."""
    state_data = state.state_data or {}
    execution_mode = state_data.get('execution_mode', 'local')
    llm_provider = state_data.get('llm_provider', 'auto')
    runtime_profile = build_runtime_profile(state_data.get("runtime_profile") or {})
    level_limits = runtime_profile.get("limits") if isinstance(runtime_profile.get("limits"), dict) else {}
    max_time_seconds = level_limits.get("max_level_runtime_seconds", DEFAULT_LEVEL_LIMITS["max_level_runtime_seconds"])

    if execution_mode == 'remote':
        remote_service = RemoteExecutionService(
            attack_state_id=state.id,
            llm_provider=llm_provider,
            max_time_seconds=max_time_seconds,
            runtime_profile=runtime_profile,
        )
        remote_service.start_assessment()
        return

    if execution_mode == 'ssh':
        ssh_service = SSHExecutionService(
            attack_state_id=state.id,
            llm_provider=llm_provider,
            max_time_seconds=max_time_seconds,
            runtime_profile=runtime_profile,
        )
        ssh_service.start_assessment()
        return

    execution_service = ExecutionService(
        attack_state_id=state.id,
        llm_provider=llm_provider,
        max_time_seconds=max_time_seconds,
        runtime_profile=runtime_profile,
    )
    execution_service.start_assessment()


def _verify_executor_is_live(executor: AttackerExecutor) -> tuple[bool, str]:
    if executor.is_ssh_executor:
        if not executor.is_remote_ready:
            return False, f"SSH executor '{executor.name}' is missing required connection details."
        ok, reason = ssh_executor.probe_connection(executor)
        if not ok:
            return False, f"SSH executor '{executor.name}' is not reachable: {reason}"
        return True, reason

    if executor.status != AttackerExecutor.Status.CONNECTED:
        return False, f"Executor '{executor.name}' is disconnected."
    if not executor.last_heartbeat:
        return False, f"Executor '{executor.name}' has no heartbeat yet."

    delta = timezone.now() - executor.last_heartbeat
    if delta > timedelta(seconds=EXECUTOR_HEARTBEAT_THRESHOLD_SECONDS):
        return False, (
            f"Executor '{executor.name}' heartbeat is stale "
            f"({int(delta.total_seconds())}s old)."
        )
    return True, "Executor heartbeat is fresh."


def _get_unified_events(state: AttackState) -> list[dict]:
    """Helper to aggregate all temporal events for timeline and replay."""
    actions = Action.objects.filter(attack_state=state)
    events = AttackTimelineEvent.objects.filter(attack_state=state).select_related('action')
    tasks = ExecutionTask.objects.filter(action__attack_state=state).select_related('action')
    alerts = DefenderAlert.objects.filter(attack_state=state)

    unified = []

    # 1. AI Actions (Decisions)
    for a in actions:
        unified.append({
            'dt': a.created_at,
            'source': 'AI',
            'type': 'DECISION',
            'desc': f"Planned: {a.name}",
            'data': {'reasoning': a.reasoning, 'parameters': a.parameters},
        })

    # 2. System Events
    for e in events:
        # Enrich with reasoning if linked to an action
        data = e.data.copy() if e.data else {}
        if e.action and e.action.reasoning:
            data['reasoning'] = e.action.reasoning
        data['phase'] = e.phase

        unified.append({
            'dt': e.created_at,
            'source': 'SYSTEM',
            'type': e.get_event_type_display(),
            'desc': e.message,
            'data': data,
        })

    # 3. Defender Alerts
    for a in alerts:
        unified.append({
            'dt': a.created_at,
            'source': 'DEFENDER',
            'type': f"ALERT {a.severity}",
            'desc': f"{a.rule_id}: {a.description}",
            'data': {'recommendation': a.recommendation},
        })

    # 4. Execution Tasks
    for t in tasks:
        # Enrich with reasoning from the parent action
        data = t.parameters.copy() if t.parameters else {}
        if t.action and t.action.reasoning:
            data['reasoning'] = t.action.reasoning

        unified.append({
            'dt': t.created_at,
            'source': 'EXECUTOR',
            'type': 'TASK_QUEUED',
            'desc': f"Queued: {t.action_name}",
            'data': data,
        })
        if t.status in ('COMPLETED', 'FAILED'):
             unified.append({
                'dt': t.updated_at,
                'source': 'EXECUTOR',
                'type': f"TASK_{t.status}",
                'desc': f"Finished: {t.action_name}",
                'data': t.output or {'error': t.error_message},
            })

    unified.sort(key=lambda x: x['dt'])
    return unified


def _get_global_context(request: HttpRequest) -> dict[str, Any]:
    """Helper to provide global context variables (executors, targets) for navigation/modals."""
    if not request.user.is_authenticated:
        # Return empty context for unauthenticated users
        return {
            'executors': AttackerExecutor.objects.none(),
            'targets': AttackTarget.objects.none(),
            'recent_attacks': AttackState.objects.none(),
            'connected_executors': [],
            'active_targets': AttackTarget.objects.none(),
            'has_connected_executor': False,
            'has_local_executor': True,
            'has_active_target': False,
            'active_context': None,
            'agentic_architecture': build_agentic_architecture_snapshot(),
        }
    
    executors = AttackerExecutor.objects.filter(Q(owner=request.user) | Q(owner__isnull=True)).order_by('-last_heartbeat')
    targets = AttackTarget.objects.filter(owner=request.user).order_by('name')
    active_context = AttackContext.objects.filter(owner=request.user, status__in=['READY', 'RUNNING']).first()
    recent_attacks = AttackState.objects.filter(owner=request.user).order_by('-created_at')[:5]

    connected_executors = [executor for executor in executors if executor.is_remote_ready]
    active_targets = targets.filter(is_active=True)

    latest_attack = recent_attacks[0] if recent_attacks else None

    return {
        'executors': executors,
        'targets': targets,
        'recent_attacks': recent_attacks,
        'connected_executors': connected_executors,
        'active_targets': active_targets,
        'has_connected_executor': bool(connected_executors),
        'has_local_executor': True,
        'has_active_target': active_targets.exists(),
        'active_context': active_context,
        'agentic_architecture': build_agentic_architecture_snapshot(latest_attack),
    }


def index(request: HttpRequest) -> HttpResponse:
    """
    Displays a public landing page for signed-out visitors and the
    authenticated dashboard for signed-in users.
    """
    if not request.user.is_authenticated:
        landing_context = {
            'latest_attack': None,
            'default_llm_provider': get_config('DEFAULT_LLM_PROVIDER', 'auto'),
            **_get_global_context(request),
        }
        return render(request, 'dashboard/landing.html', landing_context)

    selected_attack_id = request.GET.get("attack_id")
    start_modal_open = selected_attack_id == "__new__" or request.GET.get("create_new_test") == "1"
    chat_phase_key = _normalize_phase_key(request.GET.get("chat_phase") or "")
    attacks_queryset = AttackState.objects.filter(owner=request.user).order_by('-updated_at')
    if selected_attack_id and str(selected_attack_id).isdigit():
        attack_state = attacks_queryset.filter(pk=int(selected_attack_id)).first() or attacks_queryset.first()
    else:
        attack_state = attacks_queryset.first()

    plan_view = None
    if attack_state:
        actions = Action.objects.filter(attack_state=attack_state).order_by('-created_at')[:10]
        tasks = ExecutionTask.objects.filter(action__attack_state=attack_state).order_by('-created_at')[:10]
        alerts = DefenderAlert.objects.filter(attack_state=attack_state).order_by('-created_at')[:5]
        plan_view = _build_plan_view_state(attack_state)
    else:
        actions = []
        tasks = []
        alerts = []

    plan_completed = False
    if attack_state and attack_state.autonomy_status == "STOPPED" and "plan completed" in attack_state.stop_reason.lower():
        plan_completed = True

    waiting_for_approval = _is_waiting_for_plan_approval(attack_state)

    phase_dashboard = _build_phase_cards(attack_state)
    current_phase_card = next((card for card in phase_dashboard["cards"] if card.get("is_current")), None)
    quick_actions = quick_action_catalog()
    quick_action_keys = {item.get("key") for item in quick_actions if isinstance(item, dict)}

    context = {
        'attack_state': attack_state,
        'actions': actions,
        'tasks': tasks,
        'alerts': alerts,
        'plan_completed': plan_completed,
        'waiting_for_approval': waiting_for_approval,
        'plan_view': plan_view,
        'phase_map': dashboard_phase_catalog(),
        'phase_dashboard': phase_dashboard,
        'current_phase_card': current_phase_card,
        'selected_attack_id': attack_state.pk if attack_state else None,
        'all_attacks': list(attacks_queryset[:20]),
        'chat_phase_key': chat_phase_key,
        'start_modal_open': start_modal_open,
        'latest_report': (plan_view or {}).get('last_report'),
        'auto_refresh_seconds': 30,
        'quick_actions': quick_actions,
        'start_idempotency_key': f"start-{uuid.uuid4().hex}",
        'quick_idempotency_key': f"quick-{uuid.uuid4().hex}",
        'show_vulnerability_analysis_fallback': 'vulnerability_analysis' not in quick_action_keys,
        **_get_global_context(request),
        'default_llm_provider': get_config('DEFAULT_LLM_PROVIDER', 'auto'),
        'agentic_architecture': build_agentic_architecture_snapshot(attack_state),
    }
    return render(request, 'dashboard/index.html', context)


@login_required(login_url='login')
def planner_map(request: HttpRequest) -> HttpResponse:
    """Dedicated page for the static planner map and selected run phase state."""
    selected_attack_id = request.GET.get("attack_id")
    attacks_queryset = AttackState.objects.filter(owner=request.user).order_by("-updated_at")
    if selected_attack_id and str(selected_attack_id).isdigit():
        attack_state = attacks_queryset.filter(pk=int(selected_attack_id)).first() or attacks_queryset.first()
    else:
        attack_state = attacks_queryset.first()

    phase_dashboard = _build_phase_cards(attack_state)
    context = {
        "attack_state": attack_state,
        "selected_attack_id": attack_state.pk if attack_state else None,
        "all_attacks": list(attacks_queryset[:20]),
        "phase_map": dashboard_phase_catalog(),
        "phase_dashboard": phase_dashboard,
        "current_phase_card": next((card for card in phase_dashboard["cards"] if card.get("is_current")), None),
        "auto_refresh_seconds": 30,
        **_get_global_context(request),
        "agentic_architecture": build_agentic_architecture_snapshot(attack_state),
    }
    return render(request, "dashboard/planner_map.html", context)


@login_required(login_url='login')
@never_cache
def agent_run_live(request: HttpRequest) -> HttpResponse:
    """Dedicated Claude Code-style live run page with a scrollable terminal."""
    selected_attack_id = request.GET.get("attack_id")
    attacks_queryset = AttackState.objects.filter(owner=request.user).order_by("-updated_at")
    if selected_attack_id and str(selected_attack_id).isdigit():
        attack_state = attacks_queryset.filter(pk=int(selected_attack_id)).first() or attacks_queryset.first()
    else:
        attack_state = attacks_queryset.first()

    actions = []
    tasks = []
    alerts = []
    terminal_events = []
    plan_view = None
    waiting_for_approval = False
    phase_dashboard = _build_phase_cards(attack_state)
    if attack_state:
        actions = list(reversed(list(Action.objects.filter(attack_state=attack_state).order_by("-created_at")[:50])))
        tasks = list(reversed(list(ExecutionTask.objects.filter(action__attack_state=attack_state).order_by("-created_at")[:50])))
        alerts = list(reversed(list(DefenderAlert.objects.filter(attack_state=attack_state).order_by("-created_at")[:20])))
        results = list(reversed(list(ExecutionResult.objects.filter(attack_state=attack_state).select_related("command").order_by("-created_at")[:80])))
        reviews = (attack_state.state_data or {}).get("level_history") or (attack_state.state_data or {}).get("phase_reviews") or []
        review_events = []
        if isinstance(reviews, list):
            for index, review in enumerate(reviews[-20:], start=1):
                if not isinstance(review, dict):
                    continue
                review_events.append(
                    {
                        "kind": "review",
                        "dt": attack_state.created_at,
                        "sequence": index,
                        "item": review,
                    }
                )
        terminal_events = (
            review_events
            +
            [{"kind": "task", "dt": task.created_at, "item": task} for task in tasks]
            + [{"kind": "action", "dt": action.created_at, "item": action} for action in actions]
            + [{"kind": "result", "dt": result.created_at, "item": result} for result in results]
        )
        terminal_events.sort(key=lambda event: (event["dt"], event.get("sequence", 9999)))
        plan_view = _build_plan_view_state(attack_state)
        waiting_for_approval = _is_waiting_for_plan_approval(attack_state)

    context = {
        "attack_state": attack_state,
        "selected_attack_id": attack_state.pk if attack_state else None,
        "all_attacks": list(attacks_queryset[:20]),
        "actions": actions,
        "tasks": tasks,
        "alerts": alerts,
        "terminal_events": terminal_events,
        "plan_view": plan_view,
        "waiting_for_approval": waiting_for_approval,
        "phase_dashboard": phase_dashboard,
        "current_phase_card": next((card for card in phase_dashboard["cards"] if card.get("is_current")), None),
        "auto_refresh_seconds": 2,
        **_get_global_context(request),
        "agentic_architecture": build_agentic_architecture_snapshot(attack_state),
    }
    return render(request, "dashboard/agent_run_live.html", context)


@login_required(login_url='login')
def attack_detail(request: HttpRequest, pk: int) -> HttpResponse:
    """Show details for a specific AttackState, including actions and timeline."""
    state = get_object_or_404(AttackState, pk=pk, owner=request.user)

    actions = Action.objects.filter(attack_state=state).order_by("created_at")
    tasks = ExecutionTask.objects.filter(action__attack_state=state).order_by("-created_at")
    alerts = DefenderAlert.objects.filter(attack_state=state).order_by("-created_at")

    consecutive_failures = 0
    for a in actions.reverse():
        if a.status == 'FAILED':
            consecutive_failures += 1
        else:
            break

    interaction_events = []
    for a in actions:
        interaction_events.append({'ts': a.created_at, 'type': 'ATTACKER', 'obj': a})
    for alert in alerts:
        interaction_events.append({'ts': alert.created_at, 'type': 'DEFENDER', 'obj': alert})
    interaction_events.sort(key=lambda x: x['ts'])

    unified_events = _get_unified_events(state)
    plan_view = _build_plan_view_state(state)

    plan_completed = False
    if state.autonomy_status == "STOPPED" and "plan completed" in state.stop_reason.lower():
        plan_completed = True

    waiting_for_approval = _is_waiting_for_plan_approval(state)

    context = {
        'attack_state': state,
        'actions': actions,
        'tasks': tasks,
        'alerts': alerts,
        'unified_events': unified_events,
        'consecutive_failures': consecutive_failures,
        'interaction_events': interaction_events,
        'plan_completed': plan_completed,
        'waiting_for_approval': waiting_for_approval,
        'plan_view': plan_view,
        'latest_report': plan_view.get('last_report'),
        'auto_refresh_seconds': 30,
        **_get_global_context(request),
    }
    return render(request, 'dashboard/attack_detail.html', context)


@login_required(login_url='login')
def attack_phase_detail(request: HttpRequest, pk: int, phase_key: str) -> HttpResponse:
    state = get_object_or_404(AttackState, pk=pk, owner=request.user)
    selected_tab = (request.GET.get("tab") or "overview").strip().lower()
    if selected_tab not in {"overview", "plan", "outputs", "review", "timeline"}:
        selected_tab = "overview"
    phase_detail = _build_phase_detail_payload(state, phase_key)
    context = {
        "attack_state": state,
        "phase_detail": phase_detail,
        "selected_tab": selected_tab,
        "phase_dashboard": _build_phase_cards(state),
        "waiting_for_approval": _is_waiting_for_plan_approval(state),
        "plan_view": _build_plan_view_state(state),
        "auto_refresh_seconds": 30,
        **_get_global_context(request),
    }
    return render(request, "dashboard/attack_phase_detail.html", context)


@login_required(login_url='login')
def assistant_page(request: HttpRequest) -> HttpResponse:
    selected_attack_id = request.GET.get("attack_id")
    chat_phase_key = _normalize_phase_key(request.GET.get("chat_phase") or "")
    attacks_queryset = AttackState.objects.filter(owner=request.user).order_by('-updated_at')
    if selected_attack_id and str(selected_attack_id).isdigit():
        attack_state = attacks_queryset.filter(pk=int(selected_attack_id)).first() or attacks_queryset.first()
    else:
        attack_state = attacks_queryset.first()

    plan_view = _build_plan_view_state(attack_state) if attack_state else None
    context = {
        "attack_state": attack_state,
        "all_attacks": list(attacks_queryset[:20]),
        "selected_attack_id": attack_state.pk if attack_state else None,
        "chat_phase_key": chat_phase_key,
        "phase_map": dashboard_phase_catalog(),
        "phase_dashboard": _build_phase_cards(attack_state),
        "latest_report": (plan_view or {}).get("last_report"),
        **_get_global_context(request),
        "agentic_architecture": build_agentic_architecture_snapshot(attack_state),
    }
    return render(request, "dashboard/assistant.html", context)


@login_required(login_url='login')
def attack_command_logs(request: HttpRequest, pk: int) -> HttpResponse:
    """Show raw command output (stdout/stderr/findings) for a given attack."""
    state = get_object_or_404(AttackState, pk=pk, owner=request.user)
    execution_results = list(state.execution_results.select_related('command').order_by('-created_at'))
    for result in execution_results:
        _enrich_result_findings_from_stdout(result)
    state.refresh_from_db()
    state_data = state.state_data if isinstance(state.state_data, dict) else {}
    quick_review = {}
    if state_data.get("run_type") == "quick_test" and state.autonomy_status == "STOPPED":
        quick_review = QuickTestService(state.id).ensure_review()

    context = {
        'attack_state': state,
        'execution_results': execution_results,
        'plan_view': _build_plan_view_state(state),
        'quick_review': quick_review,
        'auto_refresh_seconds': 30,
        **_get_global_context(request),
    }
    return render(request, 'dashboard/attack_command_logs.html', context)


@login_required(login_url='login')
def attack_replay(request: HttpRequest, pk: int) -> HttpResponse:
    """Show a sequential replay of the attack lifecycle."""
    state = get_object_or_404(AttackState, pk=pk, owner=request.user)
    unified_events = _get_unified_events(state)
    events_json = json.dumps(unified_events, cls=DjangoJSONEncoder)
    context = {
        'state': state,
        'unified_events': unified_events,
        'events_json': events_json,
    }
    return render(request, 'dashboard/replay.html', context)


@login_required(login_url='login')
def attack_plan(request: HttpRequest, pk: int) -> HttpResponse:
    """
    Dedicated view to show the full AI generated plan (Actions) for an attack.
    Highlights the current stage and completion status.
    """
    state = get_object_or_404(AttackState, pk=pk, owner=request.user)
    actions = Action.objects.filter(attack_state=state).order_by("created_at")
    plan_view = _build_plan_view_state(state)

    context = {
        'attack_state': state,
        'actions': actions,
        'plan_view': plan_view,
        'operation_history': _build_attack_run_history(state),
        'latest_report': plan_view.get('last_report'),
        'waiting_for_approval': _is_waiting_for_plan_approval(state),
        'auto_refresh_seconds': 30,
        **_get_global_context(request),
    }
    return render(request, 'dashboard/attack_plan.html', context)


@login_required(login_url='login')
@require_POST
def generate_attack_report(request: HttpRequest, pk: int) -> HttpResponse:
    state = get_object_or_404(AttackState, pk=pk, owner=request.user)
    report_service = AttackReportService(state)
    report_service.generate_report()
    return redirect('dashboard_attack_detail', pk=pk)


@login_required(login_url='login')
def latest_attack_report(request: HttpRequest, pk: int) -> HttpResponse:
    state = get_object_or_404(AttackState, pk=pk, owner=request.user)
    report_service = AttackReportService(state)
    report = report_service.latest_report()
    if not report:
        return JsonResponse({"status": "not_found"}, status=404)
    return JsonResponse(report, safe=False)


@login_required(login_url='login')
def attack_phase_reviews(request: HttpRequest, pk: int) -> HttpResponse:
    """Show detailed stored phase reviews for an attack."""
    state = get_object_or_404(AttackState, pk=pk, owner=request.user)
    plan_view = _build_plan_view_state(state)
    context = {
        'attack_state': state,
        'plan_view': plan_view,
        'phase_reviews': (state.state_data or {}).get('level_history') or (state.state_data or {}).get('phase_reviews', []),
        'auto_refresh_seconds': 30,
        **_get_global_context(request),
    }
    return render(request, 'dashboard/phase_reviews.html', context)


@login_required(login_url='login')
def test_history(request: HttpRequest) -> HttpResponse:
    """Show all initiated attack runs with their stored plans, outputs, and reviews."""
    attacks = list(AttackState.objects.filter(owner=request.user).order_by('-created_at'))
    attack_histories = [
        {
            "attack_state": attack,
            "history": _build_attack_run_history(attack),
            "plan_view": _build_plan_view_state(attack),
        }
        for attack in attacks
    ]
    context = {
        'attack_histories': attack_histories,
        **_get_global_context(request),
    }
    return render(request, 'dashboard/test_history.html', context)


@login_required(login_url='login')
@require_POST
def delete_test_history_item(request: HttpRequest, pk: int) -> HttpResponse:
    state = get_object_or_404(AttackState, pk=pk, owner=request.user)
    deleted_name = state.name
    _delete_attack_states(AttackState.objects.filter(pk=pk))
    messages.success(request, f"Deleted test run '{deleted_name}'.")
    return redirect('dashboard_test_history')


@login_required(login_url='login')
@require_POST
def delete_all_test_history(request: HttpRequest) -> HttpResponse:
    deleted_count = _delete_attack_states(AttackState.objects.filter(owner=request.user))
    if deleted_count:
        messages.success(request, f"Deleted {deleted_count} test run(s).")
    else:
        messages.info(request, "No test runs were available to delete.")
    return redirect('dashboard_test_history')


@login_required(login_url='login')
@require_POST
def start_attack(request: HttpRequest) -> HttpResponse:
    """
    Handles the 'Start Autonomous Attack' trigger from the dashboard.
    Creates a new AttackState and determines execution mode based on executor selection.
    """
    executor_id = request.POST.get('executor_id')
    target_id = request.POST.get('target_id')
    continue_attack_id = request.POST.get('continue_attack_id')
    idempotency_key = _clean_idempotency_key(request.POST.get("idempotency_key"))
    idempotent_state = _idempotent_attack_for_request(request, "start_attack")
    if idempotent_state:
        messages.info(request, "This test start request was already processed; opening the existing run.")
        return redirect(f"{reverse('dashboard_agent_run')}?attack_id={idempotent_state.id}")
    llm_provider = request.POST.get('llm_provider', 'auto')
    requested_start_phase = normalize_phase_name(request.POST.get("start_phase") or "reconnaissance")
    start_phase = requested_start_phase if is_valid_dashboard_phase(requested_start_phase, executable_only=True) else "reconnaissance"
    progression_mode = (request.POST.get("progression_mode", "manual") or "manual").strip().lower()
    install_recommended_tools = str(request.POST.get("install_recommended_tools") or "").lower() in {
        "1",
        "on",
        "true",
        "yes",
    }
    runtime_profile = build_runtime_profile(
        {
            "max_retries": request.POST.get("max_retries"),
            "retry_cooldown_seconds": request.POST.get("retry_cooldown_seconds"),
            "limits": {
                "max_step_attempts_per_level": request.POST.get("max_step_attempts_per_level"),
                "max_level_failures": request.POST.get("max_level_failures"),
                "max_level_runtime_seconds": request.POST.get("max_level_runtime_seconds"),
            },
        }
    )

    if not target_id:
        return redirect('dashboard_index')

    target = get_object_or_404(AttackTarget, pk=target_id, owner=request.user)
    target_reference = target.base_url or target.ip_address

    # Determine execution mode based on executor selection
    use_remote_executor = False
    selected_executor = None
    
    if executor_id:
        selected_executor = get_object_or_404(
            AttackerExecutor,
            Q(owner=request.user) | Q(owner__isnull=True),
            pk=executor_id,
        )
        is_live, live_reason = _verify_executor_is_live(selected_executor)
        if is_live:
            use_remote_executor = True
        else:
            messages.error(request, live_reason)
            return redirect('dashboard_index')

    existing_state = None
    if str(continue_attack_id or "").isdigit():
        existing_state = AttackState.objects.filter(pk=int(continue_attack_id), owner=request.user).first()

    if existing_state:
        state = existing_state
        restart_phase = _resolve_restart_phase(state, start_phase)
        _preserve_current_plan_history(state)
        state_data = state.state_data if isinstance(state.state_data, dict) else {}
        execution_mode = 'ssh' if selected_executor and selected_executor.is_ssh_executor else ('remote' if use_remote_executor else 'local')
        state_data["target"] = target_reference
        state_data["current_phase"] = restart_phase
        state_data["start_phase"] = restart_phase
        state_data["requested_start_phase"] = start_phase
        state_data["llm_provider"] = llm_provider
        state_data["execution_mode"] = execution_mode
        if selected_executor and use_remote_executor:
            state_data["executor_id"] = selected_executor.id
        else:
            state_data.pop("executor_id", None)
        state_data["progression_mode"] = progression_mode if progression_mode in {"manual"} else "manual"
        state_data["plan_command_lock"] = True
        state_data["runtime_profile"] = runtime_profile
        if install_recommended_tools:
            state_data[TOOL_PREFLIGHT_STATE_KEY] = build_tool_preflight_state(True)
        else:
            state_data.pop(TOOL_PREFLIGHT_STATE_KEY, None)
        state_data["test_uid"] = state_data.get("test_uid") or f"test-{state.id}"
        if idempotency_key:
            state_data["idempotency_key"] = idempotency_key
            state_data["idempotency_scope"] = "start_attack"
        state_data["completed_commands"] = _prune_completed_commands_for_restart(
            list(state_data.get("completed_commands") or []),
            restart_phase,
        )
        state_data["plan_approved"] = False
        state_data.pop("plan_rejected", None)
        state_data["architecture_version"] = AGENTIC_ARCHITECTURE_VERSION
        state.current_phase = restart_phase
        state.autonomy_status = "IDLE"
        state.stop_reason = f"Restarting test {state_data['test_uid']} from phase '{restart_phase}'."
        state.current_plan = {}
        state.state_data = state_data
        state.save(update_fields=["current_phase", "autonomy_status", "stop_reason", "current_plan", "state_data"])
    else:
        # Create new Attack State
        if use_remote_executor:
            execution_mode = 'ssh' if selected_executor and selected_executor.is_ssh_executor else 'remote'
            state = AttackState.objects.create(
                name=f"Remote Run {selected_executor.name} {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}",
                current_phase=start_phase,
                autonomy_status="IDLE",
                owner=request.user,
                state_data={
                    "target": target_reference,
                    "current_phase": start_phase,
                    "start_phase": start_phase,
                    "completed_actions": [],
                    "findings": {},
                    "llm_provider": llm_provider,
                    "architecture_version": AGENTIC_ARCHITECTURE_VERSION,
                    "execution_mode": execution_mode,
                    "executor_id": selected_executor.id,
                    "progression_mode": progression_mode if progression_mode in {"manual"} else "manual",
                    "plan_command_lock": True,
                    "runtime_profile": runtime_profile,
                    "level_history": [],
                    "script_artifacts": [],
                    "report_artifacts": [],
                    "last_report_status": "idle",
                    **(
                        {TOOL_PREFLIGHT_STATE_KEY: build_tool_preflight_state(True)}
                        if install_recommended_tools
                        else {}
                    ),
                },
            )
        else:
            state = AttackState.objects.create(
                name=f"Local Run {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}",
                current_phase=start_phase,
                autonomy_status="IDLE",
                owner=request.user,
                state_data={
                    "target": target_reference,
                    "current_phase": start_phase,
                    "start_phase": start_phase,
                    "completed_actions": [],
                    "findings": {},
                    "llm_provider": llm_provider,
                    "architecture_version": AGENTIC_ARCHITECTURE_VERSION,
                    "execution_mode": "local",
                    "progression_mode": progression_mode if progression_mode in {"manual"} else "manual",
                    "plan_command_lock": True,
                    "runtime_profile": runtime_profile,
                    "level_history": [],
                    "script_artifacts": [],
                    "report_artifacts": [],
                    "last_report_status": "idle",
                    **(
                        {TOOL_PREFLIGHT_STATE_KEY: build_tool_preflight_state(True)}
                        if install_recommended_tools
                        else {}
                    ),
                },
            )
        if not isinstance(state.state_data, dict):
            state.state_data = {}
        state.state_data["test_uid"] = state.state_data.get("test_uid") or f"test-{uuid.uuid4().hex[:12]}"
        _store_idempotency(state, idempotency_key, "start_attack")

    # Persist provider preference
    if not state.state_data:
        state.state_data = {}
    state.state_data['llm_provider'] = llm_provider
    state.state_data['architecture_version'] = AGENTIC_ARCHITECTURE_VERSION
    state.state_data['progression_mode'] = state.state_data.get('progression_mode') or "manual"
    state.state_data['runtime_profile'] = build_runtime_profile(state.state_data.get('runtime_profile') or runtime_profile)
    state.save(update_fields=['state_data'])

    # Create or update context for UI display
    if selected_executor and use_remote_executor:
        AttackContext.objects.filter(owner=request.user, status__in=['READY', 'RUNNING']).update(
            status='STOPPED',
            stop_reason='Superseded by new attack start',
            stopped_at=timezone.now()
        )

        AttackContext.objects.create(
            attacker_executor=selected_executor,
            target=target,
            owner=request.user,
            status='READY'
        )

    # Start execution based on mode
    if use_remote_executor:
        state.stop_reason = f"Remote execution started on {selected_executor.name}."
        state.save(update_fields=['stop_reason'])
        _launch_assessment(state)
    else:
        _launch_assessment(state)

    return redirect(f"{reverse('dashboard_agent_run')}?attack_id={state.id}")


@login_required(login_url='login')
@require_POST
def start_quick_test(request: HttpRequest) -> HttpResponse:
    """Start standalone quick actions outside the phased pentest planner."""
    executor_id = request.POST.get("executor_id")
    target_id = request.POST.get("target_id")
    idempotency_key = _clean_idempotency_key(request.POST.get("idempotency_key"))
    idempotent_state = _idempotent_attack_for_request(request, "quick_test")
    if idempotent_state:
        messages.info(request, "This quick test request was already processed; opening the existing run.")
        return redirect(f"{reverse('dashboard_agent_run')}?attack_id={idempotent_state.id}")
    quick_actions = selected_quick_actions(request.POST.getlist("quick_actions"))

    if not target_id:
        messages.error(request, "Select a target before starting a quick test.")
        return redirect("dashboard_index")

    target = get_object_or_404(AttackTarget, pk=target_id, owner=request.user)
    target_reference = target.base_url or target.ip_address

    use_remote_executor = False
    selected_executor = None
    execution_mode = "local"
    if executor_id:
        selected_executor = get_object_or_404(
            AttackerExecutor,
            Q(owner=request.user) | Q(owner__isnull=True),
            pk=executor_id,
        )
        is_live, live_reason = _verify_executor_is_live(selected_executor)
        if not is_live:
            messages.error(request, live_reason)
            return redirect("dashboard_index")
        use_remote_executor = True
        execution_mode = "ssh" if selected_executor.is_ssh_executor else "remote"

    state_data = {
        "target": target_reference,
        "run_type": "quick_test",
        "architecture_version": AGENTIC_ARCHITECTURE_VERSION,
        "quick_actions": quick_actions,
        "execution_mode": execution_mode,
        "progression_mode": "quick",
        "findings": {},
        "completed_actions": [],
        "level_history": [],
        "phase_reviews": [],
        "script_artifacts": [],
        "report_artifacts": [],
        "last_report_status": "idle",
        "test_uid": f"quick-{uuid.uuid4().hex[:12]}",
    }
    if idempotency_key:
        state_data["idempotency_key"] = idempotency_key
        state_data["idempotency_scope"] = "quick_test"
    if selected_executor and use_remote_executor:
        state_data["executor_id"] = selected_executor.id

    quick_action_meta = {item["key"]: item for item in quick_action_catalog()}
    state = AttackState.objects.create(
        name=f"Quick Test {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}",
        current_phase="RECONNAISSANCE",
        autonomy_status="IDLE",
        stop_reason="Quick test queued.",
        state_data=state_data,
        current_plan={
            "scope": "quick_test",
            "phase": "quick_test",
            "rationale": "Standalone quick actions selected by the operator.",
            "steps": [
                {
                    "step_number": index,
                    "action_type": action_key,
                    "name": quick_action_meta.get(action_key, {}).get("label", action_key),
                    "description": quick_action_meta.get(action_key, {}).get("description", ""),
                    "status": "pending",
                }
                for index, action_key in enumerate(quick_actions, start=1)
            ],
        },
    )

    if selected_executor and use_remote_executor and not selected_executor.is_ssh_executor:
        AttackContext.objects.filter(owner=request.user, status__in=["READY", "RUNNING"]).update(
            status="STOPPED",
            stop_reason="Superseded by quick test",
            stopped_at=timezone.now(),
        )
        AttackContext.objects.create(
            attacker_executor=selected_executor,
            target=target,
            owner=request.user,
            status="READY",
        )

    QuickTestService(state.id).start()
    messages.success(request, "Quick test started.")
    return redirect(f"{reverse('dashboard_agent_run')}?attack_id={state.id}")

@login_required(login_url='login')
@require_POST
def approve_plan(request: HttpRequest, pk: int) -> HttpResponse:
    """Approves the current plan for the given attack state."""
    state = get_object_or_404(AttackState, pk=pk, owner=request.user)
    
    if not state.state_data:
        state.state_data = {}
    state.state_data['plan_approved'] = True
    state.state_data.pop('plan_rejected', None)
    state.state_data.pop('auto_approve_generated_plan', None)
    state.state_data.pop('phase_transition_pending', None)
    state.state_data.pop('level_transition_pending', None)
    state.save(update_fields=['state_data'])

    # Auto-resume the attack
    last_context = AttackContext.objects.filter(owner=request.user).order_by('-created_at').first()
    if last_context and last_context.status == 'STOPPED':
        last_context.status = 'READY'
        last_context.save()

    state.stop_reason = "Plan approved, resuming execution."
    state.save(update_fields=['stop_reason'])
    _launch_assessment(state)

    return redirect(f"{reverse('dashboard_agent_run')}?attack_id={pk}")

@login_required(login_url='login')
@require_POST
def resume_attack(request: HttpRequest, pk: int) -> HttpResponse:
    """Resumes an existing attack state."""
    state = get_object_or_404(AttackState, pk=pk, owner=request.user)
    
    # Attempt to reactivate the last context if it was stopped
    last_context = AttackContext.objects.filter(owner=request.user).order_by('-created_at').first()
    if last_context and last_context.status == 'STOPPED':
        last_context.status = 'READY'
        last_context.save()

    state.stop_reason = "Resuming execution."
    state.save(update_fields=['stop_reason'])
    _launch_assessment(state)
    
    return redirect(f"{reverse('dashboard_agent_run')}?attack_id={pk}")

@login_required(login_url='login')
@require_POST
def retry_failed_phase(request: HttpRequest, pk: int) -> HttpResponse:
    """Reset unresolved steps in the current phase and retry them manually."""
    state = get_object_or_404(AttackState, pk=pk, owner=request.user)
    plan = state.current_plan if isinstance(state.current_plan, dict) else {}
    steps = plan.get("steps") if isinstance(plan.get("steps"), list) else []
    state_data = state.state_data if isinstance(state.state_data, dict) else {}
    completed_commands = list(state_data.get("completed_commands") or [])

    changed = False
    retry_command_ids: list[int] = []
    for step in steps:
        status = str(step.get("status") or "").lower()
        if status == "completed":
            continue
        _refresh_step_command(step, state)
        step["status"] = "pending"
        step["alternative_pending"] = False
        step["cooldown_pending"] = False
        step["next_allowed_at"] = 0
        step["command_retry_count"] = 0
        changed = True
        command_id = step.get("command_id")
        if isinstance(command_id, int):
            retry_command_ids.append(command_id)

    if retry_command_ids and completed_commands:
        state_data["completed_commands"] = [cid for cid in completed_commands if cid not in retry_command_ids]
        changed = True
    state_data["plan_approved"] = True

    if not changed:
        messages.info(request, "No failed or pending phase steps were available to retry.")
        return redirect('dashboard_attack_detail', pk=pk)

    state.current_plan = plan
    state.state_data = state_data
    state.autonomy_status = "IDLE"
    state.stop_reason = f"Manual retry requested for phase '{state.current_phase}'."
    state.save(update_fields=["current_plan", "state_data", "autonomy_status", "stop_reason"])
    _launch_assessment(state)
    messages.success(request, f"Retry started for phase '{state.current_phase}'.")
    return redirect(f"{reverse('dashboard_agent_run')}?attack_id={pk}")


@login_required(login_url='login')
@require_POST
def regenerate_phase_plan(request: HttpRequest, pk: int, phase_key: str) -> HttpResponse:
    """Force a fresh plan for a phase while preserving earlier findings/history."""
    state = get_object_or_404(AttackState, pk=pk, owner=request.user)
    normalized_phase = _normalize_phase_key(phase_key)
    if not is_valid_dashboard_phase(normalized_phase, executable_only=True):
        messages.error(request, f"Cannot restart unknown phase '{phase_key}'.")
        return redirect('dashboard_attack_detail', pk=pk)

    _preserve_current_plan_history(state)
    state_data = state.state_data if isinstance(state.state_data, dict) else {}
    retained_completed = _prune_completed_commands_for_restart(
        list(state_data.get("completed_commands") or []),
        normalized_phase,
    )
    state_data["completed_commands"] = retained_completed
    state_data["current_phase"] = normalized_phase
    state_data["start_phase"] = normalized_phase
    state_data["requested_start_phase"] = normalized_phase
    state_data["plan_approved"] = False
    state_data.pop("plan_rejected", None)
    state_data["progression_mode"] = state_data.get("progression_mode") or "manual"
    state_data["plan_command_lock"] = True
    state_data.pop("phase_transition_pending", None)
    state_data.pop("level_transition_pending", None)

    state.current_phase = normalized_phase
    state.current_plan = {}
    state.state_data = state_data
    state.autonomy_status = "IDLE"
    state.stop_reason = f"Regenerating plan for phase '{normalized_phase}'."
    state.save(update_fields=["current_phase", "current_plan", "state_data", "autonomy_status", "stop_reason"])
    StateManager(state.id).json_store.sync_from_attack_state(state)

    _launch_assessment(state)
    messages.success(request, f"Fresh plan requested for '{dashboard_phase_display_name(normalized_phase)}'. Review and approve it before execution continues.")
    return redirect('dashboard_attack_phase_detail', pk=pk, phase_key=normalized_phase)

@login_required(login_url='login')
@require_POST
def stop_attack(request: HttpRequest, pk: int) -> HttpResponse:
    """Manually stops the autonomous attack."""
    state = get_object_or_404(AttackState, pk=pk, owner=request.user)
    state_data = state.state_data if isinstance(state.state_data, dict) else {}
    plan_rejected = str(request.POST.get("reject_plan") or "").lower() in {"1", "true", "on", "yes"}
    if plan_rejected:
        rejected_plan = deepcopy(state.current_plan if isinstance(state.current_plan, dict) else {})
        rejected_steps = [
            step.get("action_type") or step.get("action") or step.get("name")
            for step in rejected_plan.get("steps", [])
            if isinstance(step, dict)
        ]
        rejection_history = state_data.get("planner_rejections")
        rejection_history = list(rejection_history) if isinstance(rejection_history, list) else []
        rejection_history.append(
            {
                "rejected_at": timezone.now().isoformat(),
                "phase": rejected_plan.get("phase") or state.current_phase,
                "rationale": rejected_plan.get("rationale") or "",
                "steps": [step for step in rejected_steps if step],
            }
        )
        state_data["planner_rejections"] = rejection_history[-5:]
        state_data["plan_approved"] = False
        state_data.pop("plan_rejected", None)
        state.current_plan = {}
        state.state_data = state_data
        state.autonomy_status = "IDLE"
        state.stop_reason = (
            "Plan rejected by operator; generating a revised plan."
            if rejected_steps
            else "Restarting plan generation."
        )
        state.save(update_fields=["current_plan", "state_data", "autonomy_status", "stop_reason"])
        _launch_assessment(state)
        return redirect(f"{reverse('dashboard_agent_run')}?attack_id={pk}")

    state.autonomy_status = "STOPPED"
    state.stop_reason = "Manual Stop via Dashboard"
    state.state_data = state_data
    state.save(update_fields=['autonomy_status', 'stop_reason', 'state_data'])

    # Close active context
    context = AttackContext.objects.filter(owner=request.user, status__in=['READY', 'RUNNING']).first()
    if context:
        context.status = 'STOPPED'
        context.stop_reason = "Manual Stop via Dashboard"
        context.stopped_at = timezone.now()
        context.save(update_fields=['status', 'stop_reason', 'stopped_at'])

    return redirect(f"{reverse('dashboard_agent_run')}?attack_id={pk}")

@login_required(login_url='login')
@auth.admin_required
def configuration(request: HttpRequest) -> HttpResponse:
    """
    View to manage system configuration and API keys.
    """
    if request.method == 'POST':
        gemini_key = request.POST.get('gemini_key', '').strip()
        openai_key = request.POST.get('openai_key', '').strip()
        groq_key = request.POST.get('groq_key', '').strip()
        nvidia_key = request.POST.get('nvidia_key', '').strip()
        default_provider = request.POST.get('default_provider', '').strip()
        openai_model = request.POST.get('openai_model', '').strip()
        openai_host = request.POST.get('openai_host', '').strip()
        gemini_model = request.POST.get('gemini_model', '').strip()
        groq_model = request.POST.get('groq_model', '').strip()
        nvidia_model = request.POST.get('nvidia_model', '').strip()
        nvidia_host = request.POST.get('nvidia_host', '').strip()
        lmstudio_model = request.POST.get('lmstudio_model', '').strip()
        lmstudio_host = request.POST.get('lmstudio_host', '').strip()
        lmstudio_timeout = request.POST.get('lmstudio_timeout_seconds', '').strip()
        lmstudio_plan_timeout = request.POST.get('lmstudio_plan_timeout_seconds', '').strip()
        lmstudio_retries = request.POST.get('lmstudio_timeout_retries', '').strip()
        lmstudio_cooldown = request.POST.get('lmstudio_retry_cooldown_seconds', '').strip()
        lmstudio_tokens_decision = request.POST.get('lmstudio_max_tokens_decision', '').strip()
        lmstudio_tokens_plan = request.POST.get('lmstudio_max_tokens_plan', '').strip()
        
        if gemini_key:
            set_config('GOOGLE_API_KEY', gemini_key)
        if openai_key:
            set_config('OPENAI_API_KEY', openai_key)
        if groq_key:
            set_config('GROQ_API_KEY', groq_key)
        if nvidia_key:
            set_config('NVIDIA_API_KEY', nvidia_key)
        if default_provider:
            set_config('DEFAULT_LLM_PROVIDER', default_provider)
        if openai_model:
            set_config('OPENAI_MODEL', openai_model)
        if openai_host:
            set_config('OPENAI_HOST', openai_host)
        if gemini_model:
            set_config('GEMINI_MODEL', gemini_model)
        if groq_model:
            set_config('GROQ_MODEL', groq_model)
        if nvidia_model:
            set_config('NVIDIA_MODEL', nvidia_model)
        if nvidia_host:
            set_config('NVIDIA_HOST', nvidia_host)
        if lmstudio_model:
            set_config('LMSTUDIO_MODEL', lmstudio_model)
        if lmstudio_host:
            set_config('LMSTUDIO_HOST', lmstudio_host)
        if lmstudio_timeout:
            set_config('LMSTUDIO_TIMEOUT_SECONDS', lmstudio_timeout)
        if lmstudio_plan_timeout:
            set_config('LMSTUDIO_PLAN_TIMEOUT_SECONDS', lmstudio_plan_timeout)
        if lmstudio_retries:
            set_config('LMSTUDIO_TIMEOUT_RETRIES', lmstudio_retries)
        if lmstudio_cooldown:
            set_config('LMSTUDIO_RETRY_COOLDOWN_SECONDS', lmstudio_cooldown)
        if lmstudio_tokens_decision:
            set_config('LMSTUDIO_MAX_TOKENS_DECISION', lmstudio_tokens_decision)
        if lmstudio_tokens_plan:
            set_config('LMSTUDIO_MAX_TOKENS_PLAN', lmstudio_tokens_plan)

        return redirect('configuration')

    context = _get_global_context(request)
    context['has_gemini_key'] = bool(get_config('GOOGLE_API_KEY', ''))
    context['has_openai_key'] = bool(get_config('OPENAI_API_KEY', ''))
    context['has_groq_key'] = bool(get_config('GROQ_API_KEY', ''))
    context['has_nvidia_key'] = bool(get_config('NVIDIA_API_KEY', ''))
    context['default_provider'] = get_config('DEFAULT_LLM_PROVIDER', 'auto')
    context['openai_model'] = get_config('OPENAI_MODEL', 'gpt-4o-mini')
    context['openai_host'] = get_config('OPENAI_HOST', 'https://api.openai.com')
    context['gemini_model'] = get_config('GEMINI_MODEL', 'gemini-2.0-flash')
    context['groq_model'] = get_config('GROQ_MODEL', 'llama3-70b-8192')
    context['nvidia_model'] = get_config('NVIDIA_MODEL', 'mistralai/mistral-small-4-119b-2603')
    context['nvidia_host'] = get_config('NVIDIA_HOST', 'https://integrate.api.nvidia.com')
    context['lmstudio_model'] = get_config('LMSTUDIO_MODEL', 'phi-4-mini-instruct')
    context['lmstudio_host'] = get_config('LMSTUDIO_HOST', 'http://localhost:1234')
    context['lmstudio_timeout_seconds'] = get_config('LMSTUDIO_TIMEOUT_SECONDS', '60')
    context['lmstudio_plan_timeout_seconds'] = get_config('LMSTUDIO_PLAN_TIMEOUT_SECONDS', '180')
    context['lmstudio_timeout_retries'] = get_config('LMSTUDIO_TIMEOUT_RETRIES', '1')
    context['lmstudio_retry_cooldown_seconds'] = get_config('LMSTUDIO_RETRY_COOLDOWN_SECONDS', '30')
    context['lmstudio_max_tokens_decision'] = get_config('LMSTUDIO_MAX_TOKENS_DECISION', '96')
    context['lmstudio_max_tokens_plan'] = get_config('LMSTUDIO_MAX_TOKENS_PLAN', '220')
    context['groq_known_models'] = GroqAdapter.KNOWN_MODELS
    
    return render(request, 'dashboard/configuration.html', context)

@require_POST
@login_required(login_url='login')
def check_llm_status(request: HttpRequest) -> JsonResponse:
    """
    Verifies the LLM provider configuration by attempting a simple generation.
    """
    try:
        data = json.loads(request.body)
        provider = data.get('provider')
        api_key = data.get('api_key')
        model = data.get('model')
        host = data.get('host')
        
        if not provider:
            return JsonResponse({'success': False, 'message': 'Provider is required.'})

        adapter = None
        
        if provider == 'gemini':
            try:
                from ai.llm.gemini import GeminiAdapter
                adapter = GeminiAdapter(model_name=model, api_key=api_key)
            except ImportError:
                return JsonResponse({'success': False, 'message': 'Gemini SDK not installed.'})
            except Exception as e:
                return JsonResponse({'success': False, 'message': f'Gemini init failed: {str(e)}'})

        elif provider == 'openai':
            try:
                from ai.llm.openai_adapter import OpenAIAdapter
                adapter = OpenAIAdapter(model=model, api_key=api_key, host=host)
            except Exception as e:
                return JsonResponse({'success': False, 'message': f'OpenAI init failed: {str(e)}'})

        elif provider == 'groq':
            try:
                from ai.llm.groq_adapter import GroqAdapter
                adapter = GroqAdapter(model=model, api_key=api_key)
            except ImportError:
                return JsonResponse({'success': False, 'message': 'Groq SDK not installed.'})
            except Exception as e:
                return JsonResponse({'success': False, 'message': f'Groq init failed: {str(e)}'})

        elif provider == 'nvidia':
            try:
                from ai.llm.nvidia_adapter import NvidiaAdapter
                adapter = NvidiaAdapter(model=model, api_key=api_key, host=host)
            except Exception as e:
                return JsonResponse({'success': False, 'message': f'NVIDIA init failed: {str(e)}'})

        elif provider == 'lmstudio':
            try:
                from ai.llm.lmstudio_adapter import LMStudioAdapter
                adapter = LMStudioAdapter(model=model, host=host)
                if not adapter._available:
                    return JsonResponse({'success': False, 'message': 'LM Studio server unreachable. Is it running on configured host?'})
            except Exception as e:
                return JsonResponse({'success': False, 'message': f'LM Studio init failed: {str(e)}'})

        else:
            return JsonResponse({'success': False, 'message': f'Unknown provider: {provider}'})

        if not adapter:
             return JsonResponse({'success': False, 'message': 'Failed to initialize adapter.'})

        # Attempt generation
        try:
            response = adapter.generate("Reply with 'OK'.")
            if response:
                return JsonResponse({'success': True, 'message': 'Connection successful!', 'response': response})
            else:
                adapter_error = getattr(adapter, 'get_last_error', lambda: None)()
                if adapter_error:
                    status = adapter_error.get('status')
                    error_type = adapter_error.get('type')
                    message = adapter_error.get('message') or 'Provider request failed.'

                    if provider == 'openai' and error_type == 'insufficient_quota':
                        return JsonResponse({
                            'success': False,
                            'message': (
                                "OpenAI quota exceeded for this API key. "
                                "Add billing or credits, or switch to another provider."
                            ),
                            'details': message,
                            'status_code': status,
                            'error_type': error_type,
                        })

                    return JsonResponse({
                        'success': False,
                        'message': message,
                        'status_code': status,
                        'error_type': error_type,
                    })

                return JsonResponse({'success': False, 'message': 'Provider returned empty response.'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': f'API Call Failed: {str(e)}'})

    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Server Error: {str(e)}'})
