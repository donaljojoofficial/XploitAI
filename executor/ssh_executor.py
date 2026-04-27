import logging


logger = logging.getLogger(__name__)


def _connect(executor):
    try:
        import paramiko
    except ImportError as exc:
        raise RuntimeError("paramiko is required for SSH executors. Add it to the environment first.") from exc

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs = {
        "hostname": executor.ip_address,
        "port": executor.ssh_port or 22,
        "username": executor.ssh_username,
        "timeout": 20,
    }
    if executor.ssh_auth_type == executor.SSHAuthType.PRIVATE_KEY:
        connect_kwargs["key_filename"] = executor.ssh_private_key_path
    else:
        connect_kwargs["password"] = executor.ssh_password

    client.connect(**connect_kwargs)
    return client


def _prefix_command(executor, command: str) -> str:
    working_directory = (executor.ssh_working_directory or "").strip()
    if not working_directory:
        return command
    return f"cd {working_directory} && {command}"


def probe_connection(executor):
    client = None
    try:
        client = _connect(executor)
        return True, "SSH connection established."
    except Exception as exc:
        logger.exception("SSH connectivity probe failed for %s", getattr(executor, "name", "unknown"))
        return False, str(exc)
    finally:
        if client:
            client.close()


def run_command(executor, command: str):
    logger.info("Executing SSH command on %s: %s", executor.name, command)
    client = None
    try:
        client = _connect(executor)
        remote_command = _prefix_command(executor, command)
        _, stdout, stderr = client.exec_command(remote_command, timeout=120)
        exit_code = stdout.channel.recv_exit_status()
        return {
            "stdout": stdout.read().decode("utf-8", errors="replace"),
            "stderr": stderr.read().decode("utf-8", errors="replace"),
            "returncode": exit_code,
        }
    except Exception as exc:
        logger.exception("SSH command execution failed for %s", getattr(executor, "name", "unknown"))
        return {"stdout": "", "stderr": str(exc), "returncode": -1, "error": str(exc)}
    finally:
        if client:
            client.close()


def run_script(executor, script_content: str, script_language: str = "python"):
    logger.info("Executing SSH script on %s using %s", executor.name, script_language)
    client = None
    language = (script_language or "python").strip().lower()
    interpreter = "python -" if language == "python" else "bash -s"
    try:
        client = _connect(executor)
        remote_command = _prefix_command(executor, interpreter)
        stdin, stdout, stderr = client.exec_command(remote_command, timeout=120)
        stdin.write(script_content or "")
        stdin.flush()
        stdin.channel.shutdown_write()
        exit_code = stdout.channel.recv_exit_status()
        return {
            "stdout": stdout.read().decode("utf-8", errors="replace"),
            "stderr": stderr.read().decode("utf-8", errors="replace"),
            "returncode": exit_code,
        }
    except Exception as exc:
        logger.exception("SSH script execution failed for %s", getattr(executor, "name", "unknown"))
        return {"stdout": "", "stderr": str(exc), "returncode": -1, "error": str(exc)}
    finally:
        if client:
            client.close()
