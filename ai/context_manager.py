"""
Operational Context Manager — XploitAI

Responsibilities:
- Manage the binding between AI Autonomy and Operational Context.
- Validate executor liveness and target availability.
- Enforce safety checks before and during autonomy.
"""

from datetime import timedelta
from django.utils import timezone
from core.models import AttackContext, AttackerExecutor

# Heartbeat threshold (e.g., 30 seconds)
HEARTBEAT_THRESHOLD = 30

class OperationalContextManager:
    """
    Mediates access to the active AttackContext.
    Used by the AutonomousController to verify it is allowed to run.
    """

    @staticmethod
    def get_active_context() -> AttackContext | None:
        """
        Returns the current context if it is READY or RUNNING.
        Returns None if no active context exists.
        """
        return AttackContext.objects.filter(
            status__in=[AttackContext.Status.READY, AttackContext.Status.RUNNING]
        ).first()

    @staticmethod
    def validate_readiness(context: AttackContext) -> tuple[bool, str]:
        """
        Checks if the context is operationally valid.
        
        Checks:
        1. Target is active.
        2. Executor is CONNECTED.
        3. Executor heartbeat is fresh.
        """
        # 1. Target Check
        if not context.target.is_active:
            return False, f"Target '{context.target.name}' is inactive."

        # 2. Executor Connection Check
        executor = context.attacker_executor
        if executor.status != AttackerExecutor.Status.CONNECTED:
            return False, f"Executor '{executor.name}' is disconnected."

        # 3. Heartbeat Freshness Check
        # FIX BUG-AI-2: Skip heartbeat check for local/simulation executors
        is_sim = (
            executor.ip_address == "127.0.0.1" or 
            "sim" in executor.name.lower() or 
            "local" in executor.name.lower()
        )
        
        if not is_sim:
            if not executor.last_heartbeat:
                return False, f"Executor '{executor.name}' has no heartbeat."
            
            delta = timezone.now() - executor.last_heartbeat
            if delta.total_seconds() > HEARTBEAT_THRESHOLD:
                return False, f"Executor '{executor.name}' heartbeat stale ({int(delta.total_seconds())}s)."

        return True, "Context is ready."

    @staticmethod
    def ensure_running_context() -> AttackContext:
        """
        Helper for the autonomy loop to assert context validity.
        Raises RuntimeError if context is invalid.
        """
        context = OperationalContextManager.get_active_context()
        if not context:
            raise RuntimeError("No active AttackContext found.")
        
        is_valid, reason = OperationalContextManager.validate_readiness(context)
        if not is_valid:
            raise RuntimeError(f"AttackContext invalid: {reason}")
            
        return context