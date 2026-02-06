from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from core.models import AttackerExecutor

def executor_management(request):
    """
    View to list registered attacker executors and manage their status.
    """
    if request.method == 'POST':
        # Handle Deletion (Cleanup of stale executors)
        if 'delete_executor' in request.POST:
            executor_id = request.POST.get('executor_id')
            executor = get_object_or_404(AttackerExecutor, pk=executor_id)
            executor.delete()
            messages.success(request, f"Executor '{executor.name}' removed.")
            return redirect('executor_management')

    # Fetch all executors
    executors = AttackerExecutor.objects.all().order_by('-last_heartbeat')
    
    context = {
        'executors': executors,
    }
    return render(request, 'dashboard/executor_management.html', context)