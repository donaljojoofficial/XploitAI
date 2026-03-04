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
from typing import Any

from django.shortcuts import render, get_object_or_404, redirect
from . import auth
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from django.core.serializers.json import DjangoJSONEncoder

from core.models import AttackState, Action, AttackTimelineEvent, ExecutionTask, DefenderAlert, AttackerExecutor, AttackTarget, AttackContext
from ai.autonomy import AutonomousController
from core.config import get_config, set_config
from ai.llm.groq_adapter import GroqAdapter

logger = logging.getLogger(__name__)


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

    if attack_state:
        actions = Action.objects.filter(attack_state=attack_state).order_by('-created_at')[:10]
        tasks = ExecutionTask.objects.filter(action__attack_state=attack_state).order_by('-created_at')[:10]
        alerts = DefenderAlert.objects.filter(attack_state=attack_state).order_by('-created_at')[:5]
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
        'default_llm_provider': get_config('DEFAULT_LLM_PROVIDER', 'gemini'),
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
        **_get_global_context(),
    }
    return render(request, 'dashboard/attack_detail.html', context)


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
        **_get_global_context(),
    }
    return render(request, 'dashboard/attack_plan.html', context)


@login_required(login_url='login')
@require_POST
def start_attack(request: HttpRequest) -> HttpResponse:
    """
    Handles the 'Start Autonomous Attack' trigger from the dashboard.
    Creates a new AttackState and AttackContext, then starts the controller.
    """
    executor_id = request.POST.get('executor_id')
    target_id = request.POST.get('target_id')
    llm_provider = request.POST.get('llm_provider', 'auto')

    if not executor_id or not target_id:
        return redirect('dashboard_index')

    # 1. Create new Attack State
    state = AttackState.objects.create(
        name=f"Autonomous Run {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}",
        current_phase="RECONNAISSANCE",
        autonomy_status="IDLE"
    )
    
    # Persist provider preference
    if not state.state_data:
        state.state_data = {}
    state.state_data['llm_provider'] = llm_provider
    state.save(update_fields=['state_data'])

    # 2. Create Operational Context
    executor = get_object_or_404(AttackerExecutor, pk=executor_id)
    target = get_object_or_404(AttackTarget, pk=target_id)

    # Close any existing active contexts
    AttackContext.objects.filter(status__in=['READY', 'RUNNING']).update(
        status='STOPPED',
        stop_reason='Superseded by new attack start',
        stopped_at=timezone.now()
    )

    AttackContext.objects.create(
        attacker_executor=executor,
        target=target,
        status='READY'
    )

    # 3. Initialize Controller and Request Plan (Do not start loop yet)
    controller = AutonomousController(attack_state_id=state.id, llm_provider=llm_provider)
    controller.request_initial_plan()

    return redirect('dashboard_index')

@login_required(login_url='login')
@require_POST
def approve_plan(request: HttpRequest, pk: int) -> HttpResponse:
    """Approves the current plan for the given attack state."""
    state = get_object_or_404(AttackState, pk=pk)
    
    # FIX BUG-AI-3: Read provider before mutating state_data to avoid race/overwrite issues
    llm_provider = (state.state_data or {}).get('llm_provider', 'auto')

    if not state.state_data:
        state.state_data = {}
    state.state_data['plan_approved'] = True
    state.save(update_fields=['state_data'])

    # Auto-resume the attack
    last_context = AttackContext.objects.order_by('-created_at').first()
    if last_context and last_context.status == 'STOPPED':
        last_context.status = 'READY'
        last_context.save()

    controller = AutonomousController(attack_state_id=state.id, llm_provider=llm_provider)
    controller.start()

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

    llm_provider = (state.state_data or {}).get('llm_provider', 'auto')
    controller = AutonomousController(attack_state_id=state.id, llm_provider=llm_provider)
    controller.start()
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

@auth.admin_required
@login_required(login_url='login')
def configuration(request: HttpRequest) -> HttpResponse:
    """
    View to manage system configuration and API keys.
    """
    if request.method == 'POST':
        gemini_key = request.POST.get('gemini_key', '').strip()
        claude_key = request.POST.get('claude_key', '').strip()
        groq_key = request.POST.get('groq_key', '').strip()
        default_provider = request.POST.get('default_provider', '').strip()
        claude_model = request.POST.get('claude_model', '').strip()
        gemini_model = request.POST.get('gemini_model', '').strip()
        groq_model = request.POST.get('groq_model', '').strip()
        ollama_model = request.POST.get('ollama_model', '').strip()
        ollama_host = request.POST.get('ollama_host', '').strip()
        
        if gemini_key:
            set_config('GOOGLE_API_KEY', gemini_key)
        if claude_key:
            set_config('ANTHROPIC_API_KEY', claude_key)
        if groq_key:
            set_config('GROQ_API_KEY', groq_key)
        if default_provider:
            set_config('DEFAULT_LLM_PROVIDER', default_provider)
        if claude_model:
            set_config('ANTHROPIC_MODEL', claude_model)
        if gemini_model:
            set_config('GEMINI_MODEL', gemini_model)
        if groq_model:
            set_config('GROQ_MODEL', groq_model)
        if ollama_model:
            set_config('OLLAMA_MODEL', ollama_model)
        if ollama_host:
            set_config('OLLAMA_HOST', ollama_host)
            
        return redirect('configuration')
        
    context = _get_global_context()
    context['has_gemini_key'] = bool(get_config('GOOGLE_API_KEY', ''))
    context['has_claude_key'] = bool(get_config('ANTHROPIC_API_KEY', ''))
    context['has_groq_key'] = bool(get_config('GROQ_API_KEY', ''))
    context['default_provider'] = get_config('DEFAULT_LLM_PROVIDER', 'gemini')
    context['claude_model'] = get_config('ANTHROPIC_MODEL', 'claude-3-5-sonnet-20240620')
    context['gemini_model'] = get_config('GEMINI_MODEL', 'gemini-2.0-flash')
    context['groq_model'] = get_config('GROQ_MODEL', 'llama3-70b-8192')
    context['ollama_model'] = get_config('OLLAMA_MODEL', 'llama3.2:1b')
    context['ollama_host'] = get_config('OLLAMA_HOST', 'http://localhost:11434')
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

        elif provider == 'claude':
            try:
                from ai.llm.anthropic import AnthropicAdapter
                adapter = AnthropicAdapter(model_name=model, api_key=api_key)
            except Exception as e:
                return JsonResponse({'success': False, 'message': f'Claude init failed: {str(e)}'})

        elif provider == 'groq':
            try:
                from ai.llm.groq_adapter import GroqAdapter
                adapter = GroqAdapter(model=model, api_key=api_key)
            except ImportError:
                return JsonResponse({'success': False, 'message': 'Groq SDK not installed.'})
            except Exception as e:
                return JsonResponse({'success': False, 'message': f'Groq init failed: {str(e)}'})

        elif provider == 'ollama':
            try:
                from ai.llm.ollama_adapter import OllamaAdapter
                adapter = OllamaAdapter(model=model)
                if not adapter._client:
                    return JsonResponse({'success': False, 'message': 'Ollama server unreachable. Is it running?'})
            except ImportError:
                return JsonResponse({'success': False, 'message': 'Ollama SDK not installed.'})
            except Exception as e:
                return JsonResponse({'success': False, 'message': f'Ollama init failed: {str(e)}'})

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
                return JsonResponse({'success': False, 'message': 'Provider returned empty response.'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': f'API Call Failed: {str(e)}'})

    except Exception as e:
        return JsonResponse({'success': False, 'message': f'Server Error: {str(e)}'})
