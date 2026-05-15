from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from core.models import AttackerExecutor
from .forms import AttackerExecutorForm

@login_required(login_url='login')
def executor_management(request):
    """
    View to list registered attacker executors and manage their status.
    """
    form = AttackerExecutorForm()
    if request.method == 'POST':
        if 'save_executor' in request.POST:
            form = AttackerExecutorForm(request.POST)
            if form.is_valid():
                executor = form.save(commit=False)
                executor.owner = request.user
                if AttackerExecutor.objects.filter(owner=request.user, name=executor.name).exists():
                    form.add_error('name', 'You already have an executor with this name.')
                    messages.warning(request, "Please correct the executor form and try again.")
                    executors = AttackerExecutor.objects.filter(Q(owner=request.user) | Q(owner__isnull=True)).order_by('-last_heartbeat')
                    return render(request, 'dashboard/executor_management.html', {'executors': executors, 'executor_form': form})
                if executor.executor_type == AttackerExecutor.ExecutorType.SSH:
                    executor.status = AttackerExecutor.Status.DISCONNECTED
                executor.save()
                messages.success(request, f"Executor '{executor.name}' saved.")
                return redirect('executor_management')
            messages.warning(request, "Please correct the executor form and try again.")

        # Handle Deletion (Cleanup of stale executors)
        elif 'delete_executor' in request.POST:
            executor_id = request.POST.get('executor_id')
            executor = get_object_or_404(AttackerExecutor, pk=executor_id, owner=request.user)
            executor.delete()
            messages.success(request, f"Executor '{executor.name}' removed.")
            return redirect('executor_management')

    # Fetch private executors plus shared built-in executors available to every user.
    executors = AttackerExecutor.objects.filter(Q(owner=request.user) | Q(owner__isnull=True)).order_by('-last_heartbeat')
    
    context = {
        'executors': executors,
        'executor_form': form,
    }
    return render(request, 'dashboard/executor_management.html', context)
