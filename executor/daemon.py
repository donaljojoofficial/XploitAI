"""
Executor Daemon — XploitAI

Running on: Kali Linux (Attacker VM)
Responsibilities:
- Poll Controller for pending ExecutionTasks
- Execute shell commands locally
- Capture stdout/stderr and exit codes
- Report results back to Controller

Usage:
    python3 -m executor.daemon --api-url http://controller:8000
"""

import argparse
import logging
import subprocess
import sys
import time
from typing import Optional

# Third-party dependency check
try:
    import requests
except ImportError:
    print("Error: 'requests' module is required. Install with: pip install requests")
    sys.exit(1)

from executor.contract import ExecutionRequest, ExecutionResult, ExecutionStatus

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("executor-daemon")


class ExecutorDaemon:
    def __init__(self, api_url: str, poll_interval: int = 5):
        self.api_url = api_url.rstrip("/")
        self.poll_interval = poll_interval
        self.session = requests.Session()
        logger.info(f"Executor Daemon initialized. Target: {self.api_url}")

    def run(self):
        """Main loop: Poll -> Execute -> Report."""
        logger.info("Starting polling loop...")
        while True:
            try:
                task = self.fetch_task()
                if task:
                    result = self.execute_task(task)
                    self.submit_result(result)
                else:
                    time.sleep(self.poll_interval)
            except KeyboardInterrupt:
                logger.info("Stopping daemon.")
                break
            except Exception as e:
                logger.error(f"Unexpected error in main loop: {e}")
                time.sleep(self.poll_interval)

    def fetch_task(self) -> Optional[ExecutionRequest]:
        """Poll the controller for the next task."""
        try:
            # Endpoint defined in TODO EXEC-2 (assumed path based on architecture)
            resp = self.session.get(f"{self.api_url}/api/executor/tasks/next")
            if resp.status_code == 200:
                data = resp.json()
                if not data:
                    return None

                # Deserialize manually since ExecutionRequest doesn't have from_dict yet
                return ExecutionRequest(
                    task_id=data['task_id'],
                    action_name=data['action_name'],
                    command=data['command'],
                    parameters=data.get('parameters', {}),
                    limits=data.get('limits', {})
                )
            elif resp.status_code == 204:
                # No content / No tasks
                return None
            else:
                logger.warning(f"Fetch failed: {resp.status_code} - {resp.text}")
                return None
        except requests.RequestException as e:
            logger.error(f"Network error fetching task: {e}")
            return None

    def execute_task(self, task: ExecutionRequest) -> ExecutionResult:
        """Execute the shell command."""
        logger.info(f"Executing Task {task.task_id}: {task.command}")

        start_time = time.time()

        # Default limits
        timeout = task.limits.get("timeout", 60)

        try:
            # SECURITY: This executes arbitrary commands.
            # In XploitAI, this is intentional for the Attacker VM.
            # The Controller (AI) is responsible for safety filtering before sending.
            proc = subprocess.run(
                task.command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                executable="/bin/bash"  # Force bash
            )

            duration = time.time() - start_time
            status = ExecutionStatus.COMPLETED if proc.returncode == 0 else ExecutionStatus.FAILED

            return ExecutionResult(
                task_id=task.task_id,
                status=status,
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_seconds=duration,
                artifacts=[]  # Artifact scraping not yet implemented
            )

        except subprocess.TimeoutExpired as e:
            duration = time.time() - start_time
            logger.warning(f"Task {task.task_id} timed out after {timeout}s")
            return ExecutionResult(
                task_id=task.task_id,
                status=ExecutionStatus.TIMEOUT,
                exit_code=-1,
                stdout=e.stdout or "",
                stderr=e.stderr or "",
                duration_seconds=duration,
                error_message="Execution timed out"
            )
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"Task {task.task_id} execution failed: {e}")
            return ExecutionResult(
                task_id=task.task_id,
                status=ExecutionStatus.FAILED,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                duration_seconds=duration,
                error_message=str(e)
            )

    def submit_result(self, result: ExecutionResult) -> None:
        """Send results back to the controller."""
        try:
            payload = {
                "task_id": result.task_id,
                "status": result.status,
                "exit_code": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "duration_seconds": result.duration_seconds,
                "artifacts": result.artifacts,
                "error_message": result.error_message
            }

            url = f"{self.api_url}/api/executor/tasks/{result.task_id}/result"
            resp = self.session.post(url, json=payload)

            if resp.status_code in [200, 201]:
                logger.info(f"Result for Task {result.task_id} submitted successfully.")
            else:
                logger.error(f"Failed to submit result: {resp.status_code} - {resp.text}")

        except requests.RequestException as e:
            logger.error(f"Network error submitting result: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XploitAI Executor Daemon")
    parser.add_argument("--api-url", required=True, help="URL of the XploitAI Controller")
    parser.add_argument("--interval", type=int, default=5, help="Polling interval in seconds")

    args = parser.parse_args()

    daemon = ExecutorDaemon(api_url=args.api_url, poll_interval=args.interval)
    daemon.run()