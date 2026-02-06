from django.shortcuts import render, redirect
from django.contrib import messages
from core.models import AttackTarget
from dashboard.forms import AttackTargetForm

def target_management(request):
    """
    View to list existing targets and provide a form to add new ones.
    """
    if request.method == 'POST':
        form = AttackTargetForm(request.POST)
        if form.is_valid():
            target = form.save()
            messages.success(request, f"Target '{target.name}' added successfully.")
            return redirect('target_management')
    else:
        form = AttackTargetForm()

    targets = AttackTarget.objects.all().order_by('-created_at')
    
    context = {
        'targets': targets,
        'form': form
    }
    return render(request, 'dashboard/target_management.html', context)