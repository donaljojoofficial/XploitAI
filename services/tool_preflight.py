from __future__ import annotations

from typing import Any

from django.utils import timezone


TOOL_PREFLIGHT_STATE_KEY = "tool_install_preflight"
TOOL_PREFLIGHT_TIMEOUT_SECONDS = 1800

RECOMMENDED_TOOL_PACKAGES = (
    "curl",
    "python3",
    "python3-pip",
    "pipx",
    "git",
    "jq",
    "grep",
    "dnsutils",
    "whois",
    "netcat-openbsd",
    "nmap",
    "whatweb",
    "dirsearch",
    "arjun",
    "dnsenum",
    "nikto",
    "nuclei",
    "sqlmap",
    "metasploit-framework",
    "exploitdb",
    "john",
    "hashcat",
    "hydra",
    "wpscan",
    "seclists",
)

RECOMMENDED_TOOL_INSTALL_COMMAND = (
    "if ! command -v apt-get >/dev/null 2>&1; then "
    "echo 'apt-get is required for recommended tool installation. Use a Kali/Debian executor.'; exit 2; "
    "fi; "
    "if [ \"$(id -u)\" -eq 0 ]; then SUDO=''; else SUDO='sudo -n'; fi; "
    "$SUDO apt-get update && "
    "$SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y "
    + " ".join(RECOMMENDED_TOOL_PACKAGES)
)


def build_tool_preflight_state(enabled: bool) -> dict[str, Any]:
    return {
        "enabled": bool(enabled),
        "status": "pending" if enabled else "disabled",
        "command": RECOMMENDED_TOOL_INSTALL_COMMAND,
        "packages": list(RECOMMENDED_TOOL_PACKAGES),
        "timeout_seconds": TOOL_PREFLIGHT_TIMEOUT_SECONDS,
    }


def should_run_tool_preflight(state_data: dict[str, Any] | None) -> bool:
    preflight = (state_data or {}).get(TOOL_PREFLIGHT_STATE_KEY)
    if not isinstance(preflight, dict) or not preflight.get("enabled"):
        return False
    return str(preflight.get("status") or "pending").lower() not in {"completed", "running"}


def update_tool_preflight_state(attack_state, **updates: Any) -> dict[str, Any]:
    state_data = attack_state.state_data if isinstance(attack_state.state_data, dict) else {}
    preflight = state_data.get(TOOL_PREFLIGHT_STATE_KEY)
    if not isinstance(preflight, dict):
        preflight = build_tool_preflight_state(True)
    preflight.update(
        {
            "command": RECOMMENDED_TOOL_INSTALL_COMMAND,
            "packages": list(RECOMMENDED_TOOL_PACKAGES),
            "timeout_seconds": TOOL_PREFLIGHT_TIMEOUT_SECONDS,
            "updated_at": timezone.now().isoformat(),
            **updates,
        }
    )
    state_data[TOOL_PREFLIGHT_STATE_KEY] = preflight
    attack_state.state_data = state_data
    attack_state.save(update_fields=["state_data"])
    return preflight


def command_result_summary(result: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {"returncode": -1, "stdout_excerpt": "", "stderr_excerpt": "No command result returned."}
    return {
        "returncode": result.get("returncode"),
        "stdout_excerpt": str(result.get("stdout") or "")[-4000:],
        "stderr_excerpt": str(result.get("stderr") or result.get("error") or "")[-4000:],
    }
