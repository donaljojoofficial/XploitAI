from django.db import migrations

def create_phases_and_commands(apps, schema_editor):
    Phase = apps.get_model('core', 'Phase')
    Command = apps.get_model('core', 'Command')

    # 1. Define Phases
    phases_data = [
        {"name": "reconnaissance", "description": "Identify target and technology stack"},
        {"name": "discovery", "description": "Enumerate endpoints and parameters"},
        {"name": "vulnerability_analysis", "description": "Identify weaknesses"},
        {"name": "exploitation", "description": "Attempt safe exploitation"},
        {"name": "post_exploitation", "description": "Demonstrate impact"},
    ]

    phase_objects = {}
    for p_data in phases_data:
        phase, _ = Phase.objects.get_or_create(
            name=p_data["name"], 
            defaults={"description": p_data["description"]}
        )
        phase_objects[p_data["name"]] = phase

    # 2. Define Commands mapped to Phases
    commands_data = [
        {"phase_name": "reconnaissance", "name": "HTTPHeaderFetch", "description": "Retrieve HTTP headers", "command_template": "curl -I {target}"},
        {"phase_name": "reconnaissance", "name": "TechnologyFingerprint", "description": "Identify technologies via page source", "command_template": "curl -sL {target} | grep -iE 'generator|wordpress|joomla|drupal|php' || true"},
        {"phase_name": "discovery", "name": "EndpointDiscovery", "description": "Discover directories", "command_template": "python dirsearch.py -u {target}"},
        {"phase_name": "discovery", "name": "ParameterDiscovery", "description": "Identify parameters", "command_template": "python paramspider.py -d {target}"},
    ]

    for c_data in commands_data:
        phase = phase_objects.get(c_data["phase_name"])
        if phase:
            Command.objects.update_or_create(
                name=c_data["name"],
                phase=phase,
                defaults={
                    "description": c_data["description"],
                    "command_template": c_data["command_template"]
                }
            )

def reverse_phases_and_commands(apps, schema_editor):
    Phase = apps.get_model('core', 'Phase')
    Command = apps.get_model('core', 'Command')
    
    Command.objects.all().delete()
    Phase.objects.all().delete()

class Migration(migrations.Migration):

    dependencies = [
        ('core', '0002_seed_initial_attack_state'),
    ]

    operations = [
        migrations.RunPython(create_phases_and_commands, reverse_phases_and_commands),
    ]