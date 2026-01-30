# Generated initial migration for core app (Phase 1)
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='AttackState',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(help_text='A unique name for this attack simulation scenario.', max_length=255)),
                ('current_phase', models.CharField(default='RECONNAISSANCE', help_text='The current phase of the attack in the kill chain.', max_length=50)),
                ('state_data', models.JSONField(default=dict, help_text='A JSON object storing dynamic data about the attack state, e.g., discovered hosts, vulnerabilities, compromised accounts.')),
                ('created_at', models.DateTimeField(auto_now_add=True, help_text='The timestamp when the simulation was created.')),
                ('updated_at', models.DateTimeField(auto_now=True, help_text='The timestamp of the last state update.')),
            ],
            options={
                'verbose_name': 'Attack State',
                'verbose_name_plural': 'Attack States',
                'ordering': ['-updated_at'],
            },
        ),
        migrations.CreateModel(
            name='Action',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(help_text="The name of the action to be executed (e.g., 'NmapScan').", max_length=100)),
                ('description', models.TextField(blank=True, help_text='A brief description of what this action does.')),
                ('parameters', models.JSONField(default=dict, help_text='The parameters required to execute the action.')),
                ('status', models.CharField(default='PENDING', help_text='The current status of the action.', max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True, help_text='The timestamp when the action was created.')),
                ('attack_state', models.ForeignKey(help_text='The attack simulation this action belongs to.', on_delete=django.db.models.deletion.CASCADE, related_name='actions', to='core.attackstate')),
            ],
            options={
                'verbose_name': 'Action',
                'verbose_name_plural': 'Actions',
                'ordering': ['created_at'],
            },
        ),
        migrations.CreateModel(
            name='ActionResult',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('success', models.BooleanField(default=False, help_text='Indicates whether the action executed successfully.')),
                ('output', models.JSONField(default=dict, help_text='Structured data returned by the action (e.g., open ports).')),
                ('log_message', models.TextField(blank=True, help_text="A human-readable log of the action's outcome.")),
                ('created_at', models.DateTimeField(auto_now_add=True, help_text='The timestamp when the result was recorded.')),
                ('action', models.OneToOneField(help_text='The action that produced this result.', on_delete=django.db.models.deletion.CASCADE, related_name='result', to='core.action')),
            ],
            options={
                'verbose_name': 'Action Result',
                'verbose_name_plural': 'Action Results',
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='AttackTimelineEvent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('event_type', models.CharField(choices=[('DECISION', 'Decision Proposed'), ('POLICY_APPROVED', 'Policy Approved'), ('POLICY_REJECTED', 'Policy Rejected'), ('EXECUTION', 'Execution'), ('STATE_UPDATE', 'State Update'), ('PHASE_TRANSITION', 'Phase Transition')], help_text='The type/category of this timeline event.', max_length=32)),
                ('phase', models.CharField(help_text='The kill-chain phase at the time of the event.', max_length=50)),
                ('message', models.TextField(help_text='A concise, human-readable description of the event.')),
                ('data', models.JSONField(default=dict, help_text='Optional structured data relevant to this event.')),
                ('created_at', models.DateTimeField(auto_now_add=True, help_text='The timestamp when the event was recorded.')),
                ('action', models.ForeignKey(blank=True, help_text='Related action if this event is tied to a specific action.', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='timeline_events', to='core.action')),
                ('attack_state', models.ForeignKey(help_text='The attack simulation this timeline event belongs to.', on_delete=django.db.models.deletion.CASCADE, related_name='timeline', to='core.attackstate')),
            ],
            options={
                'verbose_name': 'Attack Timeline Event',
                'verbose_name_plural': 'Attack Timeline Events',
                'ordering': ['created_at'],
            },
        ),
        migrations.AddIndex(
            model_name='attacktimelineevent',
            index=models.Index(fields=['attack_state', 'created_at'], name='core_attac_attack_s_1bc5ee_idx'),
        ),
        migrations.AddIndex(
            model_name='attacktimelineevent',
            index=models.Index(fields=['event_type'], name='core_attac_event_ty_b5d6f4_idx'),
        ),
    ]
