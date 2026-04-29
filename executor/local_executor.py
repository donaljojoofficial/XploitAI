import subprocess
import logging
import os
import platform
import shutil
import signal
import tempfile

logger = logging.getLogger(__name__)

def _run_raw_command(command: str, use_bash: bool = False, timeout_seconds: int = 120):
    args = ["bash", "-lc", command] if use_bash else command
    proc = subprocess.Popen(
        args,
        shell=not use_bash,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=not platform.system().lower().startswith("win"),
    )
    try:
        timeout = int(timeout_seconds or 0)
        stdout, stderr = proc.communicate(timeout=None if timeout <= 0 else timeout)
    except subprocess.TimeoutExpired:
        _terminate_process_tree(proc)
        raise
    return subprocess.CompletedProcess(args, proc.returncode, stdout, stderr)


def _terminate_process_tree(proc) -> None:
    if proc.poll() is not None:
        return
    is_windows = platform.system().lower().startswith("win")
    try:
        if is_windows:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True,
                text=True,
                timeout=5,
            )
        else:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def run_command(command: str, timeout_seconds: int = 120):
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

        result = _run_raw_command(command, use_bash=use_bash, timeout_seconds=timeout_seconds)

        # Common Windows failure pattern for unknown command
        if (not use_bash and is_windows and result.returncode != 0 and " is not recognized" in (result.stderr or "")):
            if shutil.which("bash"):
                logger.info("Command not recognized in cmd. Retrying via bash shell.")
                result = _run_raw_command(command, use_bash=True, timeout_seconds=timeout_seconds)

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
        return {"error": "TimeoutExpired", "stderr": f"Command timed out after {int(timeout_seconds)}s.", "returncode": -1}
    except Exception as e:
        logger.exception(f"Exception running command: {command}")
        return {"error": str(e), "stderr": str(e), "returncode": -1}


def run_script(script_content: str, script_language: str = "python", timeout_seconds: int = 120):
    """Execute generated script content through a controlled tempfile wrapper."""
    language = (script_language or "python").strip().lower()
    suffix = ".py" if language == "python" else ".sh"
    interpreter = "python" if language == "python" else "bash"

    if language == "bash" and not shutil.which("bash"):
        return {
            "stdout": "",
            "stderr": "bash runtime is not available on this executor.",
            "returncode": -1,
        }

    script_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=suffix,
            delete=False,
            encoding="utf-8",
        ) as script_file:
            script_file.write(script_content or "")
            script_path = script_file.name

        result = subprocess.run(
            [interpreter, script_path],
            capture_output=True,
            text=True,
            timeout=None if int(timeout_seconds or 0) <= 0 else timeout_seconds,
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"error": "TimeoutExpired", "stderr": f"Script timed out after {int(timeout_seconds)}s.", "returncode": -1}
    except Exception as exc:
        logger.exception("Exception running generated script")
        return {"error": str(exc), "stderr": str(exc), "returncode": -1}
    finally:
        if script_path and os.path.exists(script_path):
            try:
                os.remove(script_path)
            except OSError:
                pass
