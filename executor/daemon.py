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
import socket
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
    # Security Allowlist
    ALLOWED_COMMANDS = {
        "nmap", "echo", "whois", "nslookup", "dig", "ping", "nc", "netcat"
    }

    def __init__(self, api_url: str, poll_interval: int = 5, max_backoff: int = 60):
        self.api_url = api_url.rstrip("/")
        self.poll_interval = poll_interval
        self.max_backoff = max_backoff
        self.session = requests.Session()
        
        # Identity & Heartbeat config
        self.executor_name = socket.gethostname()
        self.ip_address = self._get_local_ip()
        self.heartbeat_interval = 10
        self.last_heartbeat = 0.0
        
        logger.info(f"Executor Daemon initialized. Target: {self.api_url}")
        logger.info(f"Identity: {self.executor_name} ({self.ip_address})")

    def _get_local_ip(self) -> str:
        """Determine local IP address."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    def send_heartbeat(self):
        """Send presence signal to controller."""
        try:
            # Assumes controller mounts executor URLs at /api/executor/
            self.session.post(
                f"{self.api_url}/api/executor/heartbeat/",
                json={"name": self.executor_name, "ip_address": self.ip_address},
                timeout=5
            )
        except Exception as e:
            logger.warning(f"Heartbeat failed: {e}")

    def run(self):
        """Main loop: Poll -> Execute -> Report."""
        logger.info("Starting polling loop...")
        
        # Initial heartbeat
        self.send_heartbeat()
        self.last_heartbeat = time.time()
        
        consecutive_failures = 0

        while True:
            # Periodic heartbeat
            if time.time() - self.last_heartbeat > self.heartbeat_interval:
                self.send_heartbeat()
                self.last_heartbeat = time.time()

            try:
                task = self.fetch_task()

                # Connection successful if we reached here
                if consecutive_failures > 0:
                    logger.info("Connection to Controller restored.")
                    consecutive_failures = 0

                if task:
                    result = self.execute_task(task)
                    self.submit_result_with_retry(result)
                else:
                    time.sleep(self.poll_interval)

            except requests.RequestException as e:
                consecutive_failures += 1
                wait_time = self._calculate_backoff(consecutive_failures)
                logger.warning(f"Connection error: {e}. Retrying in {wait_time}s (Attempt {consecutive_failures})...")
                time.sleep(wait_time)

            except KeyboardInterrupt:
                logger.info("Stopping daemon.")
                break
            except Exception as e:
                logger.error(f"Unexpected error in main loop: {e}")
                time.sleep(self.poll_interval)

    def _calculate_backoff(self, failures: int) -> int:
        """Calculate exponential backoff time."""
        # interval * 2^(failures-1)
        backoff = self.poll_interval * (2 ** (failures - 1))
        return min(backoff, self.max_backoff)

    def fetch_task(self) -> Optional[ExecutionRequest]:
        """Poll the controller for the next task."""
        # Endpoint defined in TODO EXEC-2 (assumed path based on architecture)
        resp = self.session.get(f"{self.api_url}/api/executor/tasks/next", timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            if not data:
                return None

            params = data.get('parameters', {})
            # Support command in parameters (new schema) or top-level (legacy)
            cmd = data.get('command') or params.get('command')

            # Deserialize manually since ExecutionRequest doesn't have from_dict yet
            return ExecutionRequest(
                task_id=data['task_id'],
                action_name=data['action_name'],
                command=cmd,
                parameters=params,
                limits=data.get('limits', {})
            )
        elif resp.status_code == 204:
            # No content / No tasks
            return None
        else:
            resp.raise_for_status()
            return None

    def execute_task(self, task: ExecutionRequest) -> ExecutionResult:
        """Execute the shell command."""
        logger.info(f"Executing Task {task.task_id}: {task.command}")

        start_time = time.time()

        # Default limits
        timeout = task.limits.get("timeout", 60)

        # Security Check (Executor-side)
        cmd_parts = (task.command or "").strip().split()
        if not cmd_parts:
            return ExecutionResult(
                task_id=task.task_id,
                status=ExecutionStatus.FAILED,
                exit_code=-1,
                stdout="",
                stderr="Empty command",
                duration_seconds=0,
                error_message="Empty command"
            )

        # Enforce Allowlist
        binary = cmd_parts[0]
        # Handle paths (e.g. /usr/bin/nmap -> nmap)
        if "/" in binary:
            binary = binary.split("/")[-1]

        if binary not in self.ALLOWED_COMMANDS:
            return ExecutionResult(
                task_id=task.task_id,
                status=ExecutionStatus.FAILED,
                exit_code=-1,
                stdout="",
                stderr=f"Rejected command (not allowed): {task.command}",
                duration_seconds=0,
                error_message=f"Rejected command (not allowed): {task.command}"
            )

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

    def submit_result_with_retry(self, result: ExecutionResult) -> None:
        """Submit result with internal retry loop for resilience."""
        failures = 0
        while True:
            try:
                self.submit_result(result)
                return
            except requests.RequestException as e:
                # If it's a client error (4xx), don't retry forever (except maybe 408/429)
                if isinstance(e, requests.HTTPError) and 400 <= e.response.status_code < 500:
                    if e.response.status_code not in [408, 429]:
                        logger.error(f"Client error submitting result: {e}. Dropping result.")
                        return

                failures += 1
                wait_time = self._calculate_backoff(failures)
                logger.error(f"Failed to submit result (Task {result.task_id}): {e}. Retrying in {wait_time}s...")
                time.sleep(wait_time)

    def submit_result(self, result: ExecutionResult) -> None:
        """Send results back to the controller."""
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
        resp = self.session.post(url, json=payload, timeout=10)
        resp.raise_for_status()
        logger.info(f"Result for Task {result.task_id} submitted successfully.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XploitAI Executor Daemon")
    parser.add_argument("--api-url", required=True, help="URL of the XploitAI Controller")
    parser.add_argument("--interval", type=int, default=5, help="Polling interval in seconds")

    args = parser.parse_args()

    daemon = ExecutorDaemon(api_url=args.api_url, poll_interval=args.interval)
    daemon.run()