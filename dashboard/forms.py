from django import forms
from core.models import AttackTarget

class AttackTargetForm(forms.ModelForm):
    class Meta:
        model = AttackTarget
        fields = ['name', 'ip_address', 'operating_system', 'vulnerability_profile', 'is_active']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'w-full bg-gray-900 border border-gray-700 text-gray-200 rounded p-2 focus:border-accent focus:ring-1 focus:ring-accent outline-none', 'placeholder': 'e.g. Target-Alpha'}),
            'ip_address': forms.TextInput(attrs={'class': 'w-full bg-gray-900 border border-gray-700 text-gray-200 rounded p-2 focus:border-accent focus:ring-1 focus:ring-accent outline-none', 'placeholder': 'e.g. 10.0.2.15'}),
            'operating_system': forms.TextInput(attrs={'class': 'w-full bg-gray-900 border border-gray-700 text-gray-200 rounded p-2 focus:border-accent focus:ring-1 focus:ring-accent outline-none', 'placeholder': 'e.g. Ubuntu 20.04'}),
            'vulnerability_profile': forms.TextInput(attrs={'class': 'w-full bg-gray-900 border border-gray-700 text-gray-200 rounded p-2 focus:border-accent focus:ring-1 focus:ring-accent outline-none'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'w-4 h-4 bg-gray-900 border-gray-700 rounded text-accent focus:ring-accent'}),
        }