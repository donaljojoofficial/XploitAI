# Generated manually for per-user data isolation and shared built-in executors.

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models
from django.db.models import Q


SHARED_EXECUTOR_NAMES = {
    "wsl-executor",
    "wsl executor",
    "terminal",
    "terminal executor",
}


def mark_builtin_executors_shared(apps, schema_editor):
    AttackerExecutor = apps.get_model("core", "AttackerExecutor")
    for executor in AttackerExecutor.objects.all():
        if executor.name.strip().lower() in SHARED_EXECUTOR_NAMES:
            executor.owner_id = None
            executor.save(update_fields=["owner"])


def restore_shared_executors_to_first_user(apps, schema_editor):
    User = apps.get_model("auth", "User")
    AttackerExecutor = apps.get_model("core", "AttackerExecutor")
    first_user = User.objects.order_by("id").first()
    if not first_user:
        return
    AttackerExecutor.objects.filter(owner__isnull=True).update(owner_id=first_user.id)


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0019_attackcontext_owner"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterField(
            model_name="attackerexecutor",
            name="owner",
            field=models.ForeignKey(
                blank=True,
                help_text="The user who owns this executor. Empty means this is a shared built-in executor.",
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="attacker_executors",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AlterField(
            model_name="attackerexecutor",
            name="name",
            field=models.CharField(
                help_text="Human-readable identifier for this attacker machine",
                max_length=100,
            ),
        ),
        migrations.AlterField(
            model_name="attacktarget",
            name="name",
            field=models.CharField(
                help_text="Human-readable identifier for this target system",
                max_length=100,
            ),
        ),
        migrations.RunPython(mark_builtin_executors_shared, restore_shared_executors_to_first_user),
        migrations.AddConstraint(
            model_name="attackerexecutor",
            constraint=models.UniqueConstraint(
                condition=Q(owner__isnull=False),
                fields=("owner", "name"),
                name="unique_executor_name_per_owner",
            ),
        ),
        migrations.AddConstraint(
            model_name="attackerexecutor",
            constraint=models.UniqueConstraint(
                condition=Q(owner__isnull=True),
                fields=("name",),
                name="unique_shared_executor_name",
            ),
        ),
        migrations.AddConstraint(
            model_name="attacktarget",
            constraint=models.UniqueConstraint(
                fields=("owner", "name"),
                name="unique_target_name_per_owner",
            ),
        ),
    ]
