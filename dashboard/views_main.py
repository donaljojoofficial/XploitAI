from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from core.models import AttackState, Action, DefenderAlert, AttackerExecutor, AttackTarget, AttackContext

@login_required(login_url='login')
def index(request):
    """
    Dashboard Home / Mission Control.
    Displays system status, recent activity, and control options using the new template.
    """
    # Fetch the latest attack state (Mission Control)
    attack_state = AttackState.objects.filter(owner=request.user).last()

    # Fetch recent activity (current session only)
    if attack_state:
        actions = Action.objects.filter(attack_state=attack_state).order_by('-created_at')[:50]
    else:
        actions = []
    
    # Fetch recent alerts
    alerts = DefenderAlert.objects.filter(owner=request.user).order_by('-created_at')[:5]
    
    # Fetch infrastructure status
    executors = AttackerExecutor.objects.filter(Q(owner=request.user) | Q(owner__isnull=True))
    targets = AttackTarget.objects.filter(owner=request.user).exclude(base_url='')
    
    # Determine readiness for new simulations
    connected_executors = [executor for executor in executors.order_by('-last_heartbeat') if executor.is_remote_ready]
    active_targets = targets.filter(is_active=True).order_by('name')
    has_connected_executor = bool(connected_executors)
    has_active_target = active_targets.exists()
    
    # Fetch currently active operational context
    active_context = AttackContext.objects.filter(owner=request.user, status__in=['READY', 'RUNNING']).last()

    context = {
        'attack_state': attack_state,
        'actions': actions,
        'alerts': alerts,
        'executors': executors,
        'targets': targets,
        'has_connected_executor': has_connected_executor,
        'has_active_target': has_active_target,
        'default_executor': connected_executors[0] if connected_executors else None,
        'default_target': active_targets.first(),
        'connected_executors': connected_executors,
        'active_targets': active_targets,
        'active_context': active_context,
    }
    return render(request, 'dashboard/index.html', context)

@login_required(login_url='login')
def load_more_activity(request):
    """
    AJAX view to load older activity logs.
    """
    offset = int(request.GET.get('offset', 0))
    limit = 50
    attack_state = AttackState.objects.filter(owner=request.user).last()
    
    actions = []
    if attack_state:
        actions = Action.objects.filter(attack_state=attack_state).order_by('-created_at')[offset:offset+limit]
    
    return render(request, 'dashboard/partials/activity_items.html', {'actions': actions})
