from __future__ import annotations

from typing import Any


def is_timeout_result(result: dict[str, Any] | None, stderr: str = "") -> bool:
    if not isinstance(result, dict):
        return False
    error = str(result.get("error") or "")
    stderr_text = str(stderr or result.get("stderr") or "")
    if error == "TimeoutExpired":
        return True
    if "timed out" not in stderr_text.lower() and "timeout" not in stderr_text.lower():
        return False
    return result.get("returncode") in {-1, None}


def is_terminal_command_failure(result: dict[str, Any] | None, stderr: str = "") -> bool:
    if not isinstance(result, dict):
        return False
    stderr_text = str(stderr or result.get("stderr") or result.get("error") or "").lower()
    missing_tool_markers = (
        "command not found",
        "not recognized as an internal or external command",
        "no such file or directory",
        "executable file not found",
    )
    return (
        is_timeout_result(result, stderr=stderr)
        or result.get("returncode") in {126, 127}
        or any(marker in stderr_text for marker in missing_tool_markers)
    )
