from django.db import migrations
from django.utils import timezone


def seed_initial_state(apps, schema_editor):
    AttackState = apps.get_model('core', 'AttackState')
    # Only create if none exist to keep idempotent behavior for fresh DBs
    if not AttackState.objects.exists():
        AttackState.objects.create(
            name="Initial Simulation",
            current_phase="RECONNAISSANCE",
            state_data={
                "target": {"domain": "example.com"}
            },
            created_at=timezone.now(),
            updated_at=timezone.now(),
        )


def unseed_initial_state(apps, schema_editor):
    AttackState = apps.get_model('core', 'AttackState')
    AttackState.objects.filter(name="Initial Simulation").delete()


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(seed_initial_state, unseed_initial_state),
    ]
