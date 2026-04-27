from core.models import AttackerExecutor
from executor import ssh_executor
from services.execution_service import ExecutionService


class SSHExecutionService(ExecutionService):
    def __init__(self, attack_state_id: int, *args, **kwargs):
        super().__init__(attack_state_id, *args, **kwargs)
        attack_state = self.state_manager.get_attack_state()
        executor_id = (attack_state.state_data or {}).get("executor_id")
        self.executor = AttackerExecutor.objects.get(id=executor_id)
        self.execution_mode = "ssh"
        self.command_runner = lambda command: ssh_executor.run_command(self.executor, command)
        self.script_runner = lambda script_content, script_language="python": ssh_executor.run_script(
            self.executor,
            script_content,
            script_language=script_language,
        )
