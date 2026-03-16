import subprocess
import logging
import os
import platform
import shutil

logger = logging.getLogger(__name__)

def _run_raw_command(command: str, use_bash: bool = False):
    if use_bash:
        # Use bash shell when a Unix-style toolchain is expected.
        return subprocess.run(
            ["bash", "-lc", command],
            capture_output=True,
            text=True,
            timeout=120
        )

    return subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=120
    )


def run_command(command: str):
    """
    Runs a shell command locally using subprocess.
    """
    logger.info(f"Executing local command: {command}")
    try:
        # Using shell=True is a security risk if the command is from untrusted input.
        # Here, we trust that commands are constructed from the secure command_map.json.
        use_bash = False
        is_windows = platform.system().lower().startswith("win")

        # If Windows and command looks like Unix pipes/grep/curl, run via bash if available.
        if is_windows and shutil.which("bash"):
            if any(token in command for token in ["|", "grep", "curl", "sed", "awk", "||"]):
                logger.info("Windows environment detected and bash available; running command via bash")
                use_bash = True

        result = _run_raw_command(command, use_bash=use_bash)

        # Common Windows failure pattern for unknown command
        if (not use_bash and is_windows and result.returncode != 0 and " is not recognized" in (result.stderr or "")):
            if shutil.which("bash"):
                logger.info("Command not recognized in cmd. Retrying via bash shell.")
                result = _run_raw_command(command, use_bash=True)

        if result.returncode != 0:
            logger.warning(f"Command failed with return code {result.returncode}: {result.stderr}")

        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }

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