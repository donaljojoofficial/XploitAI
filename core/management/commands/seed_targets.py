from django.core.management.base import BaseCommand
from core.models import AttackTarget

class Command(BaseCommand):
    help = 'Seeds the database with initial AttackTarget configurations'

    def handle(self, *args, **options):
        targets = [
            {
                "name": "Target-Alpha (Ubuntu)",
                "ip_address": "192.168.1.105",
                "operating_system": "Ubuntu 20.04 LTS",
                "vulnerability_profile": "Standard-Lab-Build",
                "is_active": True
            },
            {
                "name": "Target-Beta (Windows)",
                "ip_address": "192.168.1.110",
                "operating_system": "Windows Server 2019",
                "vulnerability_profile": "Legacy-App-Server",
                "is_active": False
            }
        ]

        for t_data in targets:
            target, created = AttackTarget.objects.get_or_create(
                name=t_data['name'],
                defaults=t_data
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f"Created target: {target.name}"))
            else:
                self.stdout.write(f"Target already exists: {target.name}")
