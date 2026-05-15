from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django import forms
from core.models import AttackTarget
from django.contrib.auth.models import User

class WebTargetForm(forms.ModelForm):
    """Form focused on Web Targets (Phase 2)."""
    class Meta:
        model = AttackTarget
        fields = ['name', 'base_url', 'operating_system', 'vulnerability_profile', 'is_active']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'w-full bg-gray-900 border border-gray-700 text-gray-200 rounded p-2 focus:border-accent focus:ring-1 focus:ring-accent outline-none', 'placeholder': 'Target Name'}),
            'base_url': forms.URLInput(attrs={'class': 'w-full bg-gray-900 border border-gray-700 text-gray-200 rounded p-2 focus:border-accent focus:ring-1 focus:ring-accent outline-none', 'placeholder': 'http://localhost:3000'}),
            'operating_system': forms.TextInput(attrs={'class': 'w-full bg-gray-900 border border-gray-700 text-gray-200 rounded p-2 focus:border-accent focus:ring-1 focus:ring-accent outline-none', 'placeholder': 'e.g. Ubuntu 20.04'}),
            'vulnerability_profile': forms.TextInput(attrs={'class': 'w-full bg-gray-900 border border-gray-700 text-gray-200 rounded p-2 focus:border-accent focus:ring-1 focus:ring-accent outline-none', 'placeholder': 'e.g. OWASP Juice Shop'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'w-4 h-4 bg-gray-900 border-gray-700 rounded text-accent focus:ring-accent'}),
        }

@login_required(login_url='login')
def target_management(request):
    """
    View to list existing targets and provide a form to add new ones.
    Supports deleting targets and focuses on Web-based targets.
    """
    if request.method == 'POST':
        # Handle Deletion
        if 'delete_target' in request.POST:
            target_id = request.POST.get('target_id')
            target = get_object_or_404(AttackTarget, pk=target_id)
            target.delete()
            messages.success(request, f"Target '{target.name}' removed.")
            return redirect('target_management')

        form = WebTargetForm(request.POST)
        if form.is_valid():
            target = form.save(commit=False)
            target.owner = request.user
            target.save()
            messages.success(request, f"Target '{target.name}' added successfully.")
            return redirect('target_management')
    else:
        form = WebTargetForm()

    # Filter to show only Web Targets (Phase 2 focus) and hide legacy VM-only targets
    targets = AttackTarget.objects.filter(owner=request.user).exclude(base_url='').order_by('-created_at')
    
    context = {
        'targets': targets,
        'form': form
    }
    return render(request, 'dashboard/target_management.html', context)