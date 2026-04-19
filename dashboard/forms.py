from django import forms
from core.models import AttackTarget

class AttackTargetForm(forms.ModelForm):
    class Meta:
        model = AttackTarget
        fields = ['name', 'ip_address', 'operating_system', 'vulnerability_profile', 'is_active']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'ui-input', 'placeholder': 'e.g. Target-Alpha'}),
            'ip_address': forms.TextInput(attrs={'class': 'ui-input', 'placeholder': 'e.g. 10.0.2.15'}),
            'operating_system': forms.TextInput(attrs={'class': 'ui-input', 'placeholder': 'e.g. Ubuntu 20.04'}),
            'vulnerability_profile': forms.TextInput(attrs={'class': 'ui-input'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'h-4 w-4 rounded'}),
        }
