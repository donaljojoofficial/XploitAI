from django.core.management.base import BaseCommand
from django.utils import timezone
from core.models import AttackerExecutor, AttackTarget, AttackState, AttackContext, ExecutionTask
from ai.autonomy import AutonomousController
import time

class Command(BaseCommand):
    help = 'Starts a simulation to verify execution flow (specifically whois).'

    def handle(self, *args, **options):
        # 1. Check components
        executor = AttackerExecutor.objects.filter(status='CONNECTED').first()
        if not executor:
            self.stdout.write(self.style.ERROR("No connected executor found. Is the daemon running?"))
            return

        target = AttackTarget.objects.filter(is_active=True).first()
        if not target:
            self.stdout.write(self.style.ERROR("No active target found. Run 'seed_targets'."))
            return

        self.stdout.write(self.style.SUCCESS(f"Executor: {executor.name} ({executor.ip_address})"))
        self.stdout.write(self.style.SUCCESS(f"Target: {target.name} ({target.ip_address})"))

        # 2. Create State
        state = AttackState.objects.create(
            name=f"Verification Run {timezone.now().strftime('%H:%M:%S')}",
            current_phase="RECONNAISSANCE",
            autonomy_status="IDLE"
        )

        # 3. Setup Context
        AttackContext.objects.filter(status__in=['READY', 'RUNNING']).update(
            status='STOPPED',
            stop_reason='Superseded by CLI verification',
            stopped_at=timezone.now()
        )
        AttackContext.objects.create(attacker_executor=executor, target=target, status='READY')

        # 4. Start Controller
        self.stdout.write("Starting Autonomous Controller...")
        controller = AutonomousController(attack_state_id=state.id)
        controller.start()

        # 5. Monitor for PassiveRecon (whois)
        self.stdout.write("Waiting for PassiveRecon (whois) execution...")
        for _ in range(30):  # Wait up to 60 seconds
            task = ExecutionTask.objects.filter(
                action__attack_state=state, 
                action_name="PassiveRecon"
            ).last()
            
            if task:
                if task.status == 'COMPLETED':
                    self.stdout.write(self.style.SUCCESS(f"VERIFIED: whois executed successfully."))
                    self.stdout.write(f"Output: {task.output}")
                    return
                elif task.status == 'FAILED':
                    self.stdout.write(self.style.ERROR(f"FAILED: whois failed. Error: {task.error_message}"))
                    return
                else:
                    self.stdout.write(f"Task found. Status: {task.status}...")
            else:
                self.stdout.write("Waiting for task creation...")
            
            time.sleep(2)
            
        self.stdout.write(self.style.WARNING("Timed out waiting for task completion."))