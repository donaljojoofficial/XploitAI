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
from copy import deepcopy
from typing import Any

from django.shortcuts import render, get_object_or_404, redirect
from . import auth
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from django.core.serializers.json import DjangoJSONEncoder

from core.models import AttackState, Action, AttackTimelineEvent, ExecutionTask, DefenderAlert, AttackerExecutor, AttackTarget, AttackContext
from services.execution_service import ExecutionService
from services.remote_execution_service import RemoteExecutionService
from core.config import get_config, set_config
from ai.llm.groq_adapter import GroqAdapter

logger = logging.getLogger(__name__)

def _build_plan_view_state(state: AttackState) -> dict[str, Any]:
    """
    Build a UI-friendly, execution-aware representation of current_plan.
    Adds per-step status and summary counters for staged execution UX.
    """
    plan = deepcopy(state.current_plan or {})
    raw_steps = plan.get("steps") or []

    if not raw_steps:
        return {
            "rationale": plan.get("rationale", ""),
            "steps": [],
            "summary": {
                "total": 0,
                "completed": 0,
                "failed": 0,
                "pending": 0,
            },
            "current_step": None,
            "all_done": False,
        }

    results = (
        state.execution_results
        .select_related("command")
        .order_by("-created_at")
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
        match = latest_by_command.get(action_name)

        if match and match.status == "SUCCESS":
            item["status"] = "completed"
        elif match and match.status == "FAILED":
            item["status"] = "failed"
        else:
            item["status"] = "pending"

        item.setdefault("step_number", idx + 1)
        steps.append(item)

    # Mark a single active step when attack is running/planning.
    unresolved_idx = next(
        (i for i, s in enumerate(steps) if s["status"] in ("pending", "failed")),
        None,
    )
    if unresolved_idx is not None and state.autonomy_status in ("RUNNING", "PLANNING"):
        if steps[unresolved_idx]["status"] != "completed":
            steps[unresolved_idx]["status"] = "running"

    completed_count = sum(1 for s in steps if s["status"] == "completed")
    failed_count = sum(1 for s in steps if s["status"] == "failed")
    running_count = sum(1 for s in steps if s["status"] == "running")
    pending_count = sum(1 for s in steps if s["status"] == "pending")
    current_step = next((s for s in steps if s["status"] == "running"), None)

    return {
        "rationale": plan.get("rationale", ""),
        "steps": steps,
        "summary": {
            "total": len(steps),
            "completed": completed_count,
            "failed": failed_count,
            "running": running_count,
            "pending": pending_count,
        },
        "current_step": current_step,
        "all_done": completed_count == len(steps),
    }


def _launch_assessment(state: AttackState) -> None:
    """Start the appropriate assessment service for the state's execution mode."""
    state_data = state.state_data or {}
    execution_mode = state_data.get('execution_mode', 'local')
    llm_provider = state_data.get('llm_provider', 'auto')

    if execution_mode == 'remote':
        remote_service = RemoteExecutionService(
            attack_state_id=state.id,
            llm_provider=llm_provider,
        )
        remote_service.start_assessment()
        return

    execution_service = ExecutionService(
        attack_state_id=state.id,
        llm_provider=llm_provider,
    )
    execution_service.start_assessment()


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


def _get_global_context() -> dict[str, Any]:
    """Helper to provide global context variables (executors, targets) for navigation/modals."""
    executors = AttackerExecutor.objects.all().order_by('-last_heartbeat')
    targets = AttackTarget.objects.all().order_by('name')
    active_context = AttackContext.objects.filter(status__in=['READY', 'RUNNING']).first()
    recent_attacks = AttackState.objects.order_by('-created_at')[:5]

    connected_executors = executors.filter(status=AttackerExecutor.Status.CONNECTED)
    active_targets = targets.filter(is_active=True)

    return {
        'executors': executors,
        'targets': targets,
        'recent_attacks': recent_attacks,
        'connected_executors': connected_executors,
        'active_targets': active_targets,
        'has_connected_executor': connected_executors.exists(),
        'has_local_executor': True,
        'has_active_target': active_targets.exists(),
        'active_context': active_context,
    }


@login_required(login_url='login')
def index(request: HttpRequest) -> HttpResponse:
    """
    Displays the main dashboard using a Django template.
    Shows the latest simulation by default.
    """
    attack_state = AttackState.objects.order_by('-updated_at').first()

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

    waiting_for_approval = False
    if attack_state and attack_state.autonomy_status == "STOPPED" and "waiting for approval" in attack_state.stop_reason.lower():
        waiting_for_approval = True

    context = {
        'attack_state': attack_state,
        'actions': actions,
        'tasks': tasks,
        'alerts': alerts,
        'plan_completed': plan_completed,
        'waiting_for_approval': waiting_for_approval,
        'plan_view': plan_view,
        'default_llm_provider': get_config('DEFAULT_LLM_PROVIDER', 'auto'),
        **_get_global_context(),
    }
    return render(request, 'dashboard/index.html', context)


@login_required(login_url='login')
def attack_detail(request: HttpRequest, pk: int) -> HttpResponse:
    """Show details for a specific AttackState, including actions and timeline."""
    state = get_object_or_404(AttackState, pk=pk)

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

    waiting_for_approval = False
    if state.autonomy_status == "STOPPED" and "waiting for approval" in state.stop_reason.lower():
        waiting_for_approval = True

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
        **_get_global_context(),
    }
    return render(request, 'dashboard/attack_detail.html', context)


@login_required(login_url='login')
def attack_command_logs(request: HttpRequest, pk: int) -> HttpResponse:
    """Show raw command output (stdout/stderr/findings) for a given attack."""
    state = get_object_or_404(AttackState, pk=pk)
    execution_results = state.execution_results.select_related('command').order_by('-created_at')

    context = {
        'attack_state': state,
        'execution_results': execution_results,
        'plan_view': _build_plan_view_state(state),
        **_get_global_context(),
    }
    return render(request, 'dashboard/attack_command_logs.html', context)


@login_required(login_url='login')
def attack_replay(request: HttpRequest, pk: int) -> HttpResponse:
    """Show a sequential replay of the attack lifecycle."""
    state = get_object_or_404(AttackState, pk=pk)
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
    state = get_object_or_404(AttackState, pk=pk)
    actions = Action.objects.filter(attack_state=state).order_by("created_at")

    context = {
        'attack_state': state,
        'actions': actions,
        'plan_view': _build_plan_view_state(state),
        **_get_global_context(),
    }
    return render(request, 'dashboard/attack_plan.html', context)


@login_required(login_url='login')
@require_POST
def start_attack(request: HttpRequest) -> HttpResponse:
    """
    Handles the 'Start Autonomous Attack' trigger from the dashboard.
    Creates a new AttackState and determines execution mode based on executor selection.
    """
    executor_id = request.POST.get('executor_id')
    target_id = request.POST.get('target_id')
    llm_provider = request.POST.get('llm_provider', 'auto')

    if not target_id:
        return redirect('dashboard_index')

    target = get_object_or_404(AttackTarget, pk=target_id)
    target_reference = target.base_url or target.ip_address

    # Determine execution mode based on executor selection
    use_remote_executor = False
    selected_executor = None
    
    if executor_id:
        selected_executor = get_object_or_404(AttackerExecutor, pk=executor_id)
        # Check if the selected executor is connected
        if selected_executor.status == AttackerExecutor.Status.CONNECTED:
            use_remote_executor = True

    # Create new Attack State
    if use_remote_executor:
        state = AttackState.objects.create(
            name=f"Remote Run {selected_executor.name} {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}",
            current_phase="RECONNAISSANCE",
            autonomy_status="IDLE",
            state_data={
                "target": target_reference,
                "current_phase": "reconnaissance",
                "completed_actions": [],
                "findings": {},
                "llm_provider": llm_provider,
                "execution_mode": "remote",
                "executor_id": selected_executor.id,
            },
        )
    else:
        state = AttackState.objects.create(
            name=f"Local Run {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}",
            current_phase="RECONNAISSANCE",
            autonomy_status="IDLE",
            state_data={
                "target": target_reference,
                "current_phase": "reconnaissance",
                "completed_actions": [],
                "findings": {},
                "llm_provider": llm_provider,
                "execution_mode": "local",
            },
        )

    # Persist provider preference
    if not state.state_data:
        state.state_data = {}
    state.state_data['llm_provider'] = llm_provider
    state.save(update_fields=['state_data'])

    # Create or update context for UI display
    if selected_executor:
        AttackContext.objects.filter(status__in=['READY', 'RUNNING']).update(
            status='STOPPED',
            stop_reason='Superseded by new attack start',
            stopped_at=timezone.now()
        )

        AttackContext.objects.create(
            attacker_executor=selected_executor,
            target=target,
            status='READY'
        )

    # Start execution based on mode
    if use_remote_executor:
        state.stop_reason = f"Remote execution started on {selected_executor.name}."
        state.save(update_fields=['stop_reason'])
        _launch_assessment(state)
    else:
        _launch_assessment(state)

    return redirect('dashboard_index')

@login_required(login_url='login')
@require_POST
def approve_plan(request: HttpRequest, pk: int) -> HttpResponse:
    """Approves the current plan for the given attack state."""
    state = get_object_or_404(AttackState, pk=pk)
    
    if not state.state_data:
        state.state_data = {}
    state.state_data['plan_approved'] = True
    state.save(update_fields=['state_data'])

    # Auto-resume the attack
    last_context = AttackContext.objects.order_by('-created_at').first()
    if last_context and last_context.status == 'STOPPED':
        last_context.status = 'READY'
        last_context.save()

    state.stop_reason = "Plan approved, resuming execution."
    state.save(update_fields=['stop_reason'])
    _launch_assessment(state)

    return redirect('dashboard_attack_detail', pk=pk)

@login_required(login_url='login')
@require_POST
def resume_attack(request: HttpRequest, pk: int) -> HttpResponse:
    """Resumes an existing attack state."""
    state = get_object_or_404(AttackState, pk=pk)
    
    # Attempt to reactivate the last context if it was stopped
    last_context = AttackContext.objects.order_by('-created_at').first()
    if last_context and last_context.status == 'STOPPED':
        last_context.status = 'READY'
        last_context.save()

    state.stop_reason = "Resuming execution."
    state.save(update_fields=['stop_reason'])
    _launch_assessment(state)
    
    return redirect('dashboard_attack_detail', pk=pk)

@login_required(login_url='login')
@require_POST
def stop_attack(request: HttpRequest, pk: int) -> HttpResponse:
    """Manually stops the autonomous attack."""
    state = get_object_or_404(AttackState, pk=pk)
    
    state.autonomy_status = "STOPPED"
    state.stop_reason = "Manual Stop via Dashboard"
    state.save(update_fields=['autonomy_status', 'stop_reason'])

    # Close active context
    context = AttackContext.objects.filter(status__in=['READY', 'RUNNING']).first()
    if context:
        context.status = 'STOPPED'
        context.stop_reason = "Manual Stop via Dashboard"
        context.stopped_at = timezone.now()
        context.save(update_fields=['status', 'stop_reason', 'stopped_at'])

    return redirect('dashboard_attack_detail', pk=pk)

@login_required(login_url='login')
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
        
    context = _get_global_context()
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
