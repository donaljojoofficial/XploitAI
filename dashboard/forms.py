from django import forms
from core.models import AttackTarget

class AttackTargetForm(forms.ModelForm):
    class Meta:
        model = AttackTarget
        fields = ['name', 'ip_address', 'operating_system', 'vulnerability_profile', 'is_active']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g. Target-Alpha'}),
            'ip_address': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g. 10.0.2.15'}),
            'operating_system': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g. Ubuntu 20.04'}),
            'vulnerability_profile': forms.TextInput(attrs={'class': 'form-control'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }