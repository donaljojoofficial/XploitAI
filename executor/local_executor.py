import subprocess
import logging

logger = logging.getLogger(__name__)

def run_command(command: str):
    """
    Runs a shell command locally using subprocess.
    """
    logger.info(f"Executing local command: {command}")
    try:
        # Using shell=True is a security risk if the command is from untrusted input.
        # Here, we trust that commands are constructed from the secure command_map.json.
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=120  # 2-minute timeout
        )

        if result.returncode != 0:
            logger.warning(f"Command failed with return code {result.returncode}: {result.stderr}")

        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }

    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {command}")
        return {"error": "TimeoutExpired", "stderr": "Command timed out after 120s.", "returncode": -1}
    except Exception as e:
        logger.exception(f"Exception running command: {command}")
        return {"error": str(e), "stderr": str(e), "returncode": -1}