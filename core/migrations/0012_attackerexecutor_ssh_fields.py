from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0011_merge_20260316_2131"),
    ]

    operations = [
        migrations.AddField(
            model_name="attackerexecutor",
            name="executor_type",
            field=models.CharField(
                choices=[("DAEMON", "Daemon"), ("SSH", "SSH")],
                default="DAEMON",
                help_text="How this executor is reached by the controller.",
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="attackerexecutor",
            name="ssh_auth_type",
            field=models.CharField(
                choices=[("PASSWORD", "Password"), ("PRIVATE_KEY", "Private Key")],
                default="PASSWORD",
                help_text="Authentication mode for SSH executors.",
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="attackerexecutor",
            name="ssh_password",
            field=models.CharField(
                blank=True,
                help_text="SSH password for password-based SSH executors.",
                max_length=255,
            ),
        ),
        migrations.AddField(
            model_name="attackerexecutor",
            name="ssh_port",
            field=models.PositiveIntegerField(
                default=22,
                help_text="SSH port for direct SSH executors.",
            ),
        ),
        migrations.AddField(
            model_name="attackerexecutor",
            name="ssh_private_key_path",
            field=models.CharField(
                blank=True,
                help_text="Absolute path to the private key file for key-based SSH executors.",
                max_length=255,
            ),
        ),
        migrations.AddField(
            model_name="attackerexecutor",
            name="ssh_username",
            field=models.CharField(
                blank=True,
                help_text="SSH username used when executor_type is SSH.",
                max_length=100,
            ),
        ),
        migrations.AddField(
            model_name="attackerexecutor",
            name="ssh_working_directory",
            field=models.CharField(
                blank=True,
                help_text="Optional remote working directory used before command execution.",
                max_length=255,
            ),
        ),
    ]
