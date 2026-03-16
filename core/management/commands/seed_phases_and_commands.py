"""
Django management command to seed Phase and Command data.
"""
from django.core.management.base import BaseCommand as DjangoCommand
from core.models import Phase, Command as CommandModel


class Command(DjangoCommand):
    help = "Seed Phase and Command data for pentesting workflow."

    def handle(self, *args, **options):
        phases_data = [
            {"name": "reconnaissance", "description": "Identify target and technology stack"},
            {"name": "discovery", "description": "Enumerate endpoints and parameters"},
            {"name": "vulnerability_analysis", "description": "Identify weaknesses"},
            {"name": "exploitation", "description": "Attempt safe exploitation"},
            {"name": "post_exploitation", "description": "Demonstrate impact"},
        ]

        commands_data = [
            {
                "phase_name": "reconnaissance",
                "name": "HTTPHeaderFetch",
                "description": "Retrieve HTTP headers",
                "command_template": "curl -I {target}",
            },
            {
                "phase_name": "reconnaissance",
                "name": "TechnologyFingerprint",
                "description": "Identify technologies",
                "command_template": "whatweb {target}",
            },
            {
                "phase_name": "discovery",
                "name": "EndpointDiscovery",
                "description": "Discover directories",
                "command_template": "echo 'Discovering endpoints for {target}'",
            },
            {
                "phase_name": "discovery",
                "name": "ParameterDiscovery",
                "description": "Identify parameters",
                "command_template": "echo 'Discovering parameters for {target}'",
            },
            {
                "phase_name": "vulnerability_analysis",
                "name": "VulnerabilityScanning",
                "description": "Scan for known vulnerabilities",
                "command_template": "echo 'Scanning {target} for vulnerabilities'",
            },
            {
                "phase_name": "exploitation",
                "name": "ExploitAttempt",
                "description": "Attempt exploitation",
                "command_template": "echo 'Attempting exploitation on {target}'",
            },
            {
                "phase_name": "post_exploitation",
                "name": "ProofOfCompromise",
                "description": "Gather proof of compromise",
                "command_template": "echo 'Gathering proof from {target}'",
            },
        ]

        # Create phases
        created_phases = 0
        for phase_data in phases_data:
            phase, created = Phase.objects.get_or_create(
                name=phase_data["name"],
                defaults={"description": phase_data["description"]},
            )
            if created:
                created_phases += 1
                self.stdout.write(self.style.SUCCESS(f"Created phase: {phase.name}"))
            else:
                self.stdout.write(f"Phase already exists: {phase.name}")

        self.stdout.write(self.style.SUCCESS(f"\nTotal phases created: {created_phases}"))

        # Create commands
        created_commands = 0
        for cmd_data in commands_data:
            phase = Phase.objects.get(name=cmd_data["phase_name"])
            command, created = CommandModel.objects.get_or_create(
                name=cmd_data["name"],
                defaults={
                    "phase": phase,
                    "description": cmd_data["description"],
                    "command_template": cmd_data["command_template"],
                },
            )
            if created:
                created_commands += 1
                self.stdout.write(self.style.SUCCESS(f"Created command: {command.name}"))
            else:
                self.stdout.write(f"Command already exists: {command.name}")

        self.stdout.write(self.style.SUCCESS(f"\nTotal commands created: {created_commands}"))
