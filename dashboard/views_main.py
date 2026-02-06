from django.shortcuts import render
from core.models import AttackState, Action, DefenderAlert, AttackerExecutor, AttackTarget

def index(request):
    """
    Dashboard Home / Mission Control.
    Displays system status, recent activity, and control options using the new template.
    """
    # Fetch the latest attack state (Mission Control)
    attack_state = AttackState.objects.last()

    # Fetch recent activity (global log)
    actions = Action.objects.select_related('attack_state').order_by('-created_at')[:10]
    
    # Fetch recent alerts
    alerts = DefenderAlert.objects.all().order_by('-created_at')[:5]
    
    # Fetch infrastructure status
    executors = AttackerExecutor.objects.all()
    targets = AttackTarget.objects.all()
    
    # Determine readiness for new simulations
    has_connected_executor = executors.filter(status=AttackerExecutor.Status.CONNECTED).exists()
    has_active_target = targets.filter(is_active=True).exists()
    
    context = {
        'attack_state': attack_state,
        'actions': actions,
        'alerts': alerts,
        'executors': executors,
        'targets': targets,
        'has_connected_executor': has_connected_executor,
        'has_active_target': has_active_target,
    }
    return render(request, 'dashboard/index.html', context)