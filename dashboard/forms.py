import os

from django import forms
from core.models import AttackTarget, AttackerExecutor

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


class AttackerExecutorForm(forms.ModelForm):
    class Meta:
        model = AttackerExecutor
        fields = [
            'name',
            'executor_type',
            'ip_address',
            'ssh_port',
            'ssh_username',
            'ssh_auth_type',
            'ssh_password',
            'ssh_private_key_path',
            'ssh_working_directory',
        ]
        widgets = {
            'name': forms.TextInput(attrs={'class': 'ui-input', 'placeholder': 'e.g. Kali-SSH-01'}),
            'executor_type': forms.Select(attrs={'class': 'ui-input'}),
            'ip_address': forms.TextInput(attrs={'class': 'ui-input', 'placeholder': 'e.g. 192.168.56.10'}),
            'ssh_port': forms.NumberInput(attrs={'class': 'ui-input', 'min': 1, 'max': 65535}),
            'ssh_username': forms.TextInput(attrs={'class': 'ui-input', 'placeholder': 'e.g. kali'}),
            'ssh_auth_type': forms.Select(attrs={'class': 'ui-input'}),
            'ssh_password': forms.PasswordInput(attrs={'class': 'ui-input', 'placeholder': 'SSH password'}, render_value=True),
            'ssh_private_key_path': forms.TextInput(attrs={'class': 'ui-input', 'placeholder': 'e.g. /home/app/.ssh/id_ed25519'}),
            'ssh_working_directory': forms.TextInput(attrs={'class': 'ui-input', 'placeholder': 'Optional, e.g. /home/kali'}),
        }

    def clean(self):
        cleaned_data = super().clean()
        executor_type = cleaned_data.get('executor_type')
        ssh_auth_type = cleaned_data.get('ssh_auth_type')
        ssh_username = (cleaned_data.get('ssh_username') or '').strip()
        ssh_password = cleaned_data.get('ssh_password') or ''
        ssh_private_key_path = (cleaned_data.get('ssh_private_key_path') or '').strip()

        if executor_type == AttackerExecutor.ExecutorType.SSH:
            if not ssh_username:
                self.add_error('ssh_username', 'SSH username is required for SSH executors.')
            if ssh_auth_type == AttackerExecutor.SSHAuthType.PASSWORD and not ssh_password:
                self.add_error('ssh_password', 'SSH password is required for password-based SSH executors.')
            if ssh_auth_type == AttackerExecutor.SSHAuthType.PRIVATE_KEY and not ssh_private_key_path:
                self.add_error('ssh_private_key_path', 'Private key path is required for key-based SSH executors.')
            if ssh_private_key_path and not os.path.isabs(ssh_private_key_path):
                self.add_error('ssh_private_key_path', 'Private key path must be absolute on the controller host.')

        return cleaned_data

    def save(self, commit=True):
        instance = super().save(commit=False)
        if instance.executor_type != AttackerExecutor.ExecutorType.SSH:
            instance.ssh_username = ''
            instance.ssh_password = ''
            instance.ssh_private_key_path = ''
            instance.ssh_working_directory = ''
            instance.ssh_port = 22
        if commit:
            instance.save()
        return instance
