from django.core.management.base import BaseCommand
from core.models import AttackTarget

class Command(BaseCommand):
    help = 'Add or update a target in the database.'

    def add_arguments(self, parser):
        parser.add_argument('--name', type=str, required=True, help='Name of the target')
        parser.add_argument('--ip', type=str, required=True, help='IP address of the target')
        parser.add_argument('--os', type=str, required=True, help='Operating System')
        parser.add_argument('--vuln', type=str, default='', help='Vulnerability Profile')

    def handle(self, *args, **options):
        target, created = AttackTarget.objects.update_or_create(
            name=options['name'],
            defaults={
                'ip_address': options['ip'],
                'operating_system': options['os'],
                'vulnerability_profile': options['vuln'],
                'is_active': True
            }
        )
        
        verb = "Created" if created else "Updated"
        self.stdout.write(self.style.SUCCESS(f"{verb} target: {target.name} ({target.ip_address})"))