from __future__ import annotations

from typing import Any

DEFAULT_PROGRESS_MODE = "manual"
DEFAULT_STEP_MAX_RETRIES = 2
DEFAULT_STEP_RETRY_COOLDOWN_SECONDS = 2
DEFAULT_LEVEL_LIMITS = {
    "max_step_attempts_per_level": 5,
    "max_level_failures": 3,
    "max_level_runtime_seconds": 300,
}

_KILL_CHAIN_LABEL_MAP = {
    "reconnaissance": "RECONNAISSANCE",
    "discovery": "ENUMERATION",
    "enumeration": "ENUMERATION",
    "vulnerability_analysis": "EXPLOITATION",
    "exploitation": "EXPLOITATION",
    "privilege_escalation": "PRIVILEGE_ESCALATION",
    "post_exploitation": "PROOF_OF_COMPROMISE",
    "proof_of_compromise": "PROOF_OF_COMPROMISE",
    "completed": "COMPLETED",
}

_DASHBOARD_PHASE_KEY_MAP = {
    "reconnaissance": "reconnaissance",
    "information_gathering": "reconnaissance",
    "enumeration": "discovery",
    "discovery": "discovery",
    "vulnerability_analysis": "vulnerability_analysis",
    "exploitation": "exploitation",
    "privilege_escalation": "exploitation",
    "post_exploitation": "post_exploitation",
    "proof_of_compromise": "post_exploitation",
    "completed": "completed",
}

_STAGE_LABEL_MAP = {
    "reconnaissance": "planning_recon",
    "discovery": "scanning",
    "vulnerability_analysis": "scanning",
    "exploitation": "exploitation",
    "post_exploitation": "maintaining_access_payload",
    "proof_of_compromise": "proof_of_compromise",
    "completed": "proof_of_compromise",
}

_DASHBOARD_PHASES = [
    {
        "key": "reconnaissance",
        "display_name": "Information Gathering / Reconnaissance",
        "description": "Establish target context, surface area, and initial intelligence.",
        "normalized_key": "reconnaissance",
        "is_executable": True,
        "is_synthetic": False,
    },
    {
        "key": "discovery",
        "display_name": "Enumeration",
        "description": "Enumerate reachable endpoints, services, and parameters.",
        "normalized_key": "discovery",
        "is_executable": True,
        "is_synthetic": False,
    },
    {
        "key": "vulnerability_analysis",
        "display_name": "Vulnerability Analysis",
        "description": "Assess weaknesses and identify viable attack paths.",
        "normalized_key": "vulnerability_analysis",
        "is_executable": True,
        "is_synthetic": False,
    },
    {
        "key": "exploitation",
        "display_name": "Exploitation",
        "description": "Execute approved exploitation steps against validated opportunities.",
        "normalized_key": "exploitation",
        "is_executable": True,
        "is_synthetic": False,
    },
    {
        "key": "post_exploitation",
        "display_name": "Post-Exploitation / Proof",
        "description": "Demonstrate impact, collect proof, and capture operator evidence.",
        "normalized_key": "post_exploitation",
        "is_executable": True,
        "is_synthetic": False,
    },
    {
        "key": "completed",
        "display_name": "Completion / Report",
        "description": "Summarize the run, reviews, findings, and generated reporting artifacts.",
        "normalized_key": "completed",
        "is_executable": False,
        "is_synthetic": True,
    },
]


def normalize_phase_name(phase: Any) -> str:
    return str(phase or "").strip().lower().replace(" ", "_")


def dashboard_phase_catalog(executable_only: bool = False) -> list[dict[str, Any]]:
    phases = [dict(item) for item in _DASHBOARD_PHASES]
    if executable_only:
        phases = [item for item in phases if item["is_executable"]]
    return phases


def dashboard_phase_keys(executable_only: bool = False) -> list[str]:
    return [item["key"] for item in dashboard_phase_catalog(executable_only=executable_only)]


def dashboard_phase_meta(phase: Any) -> dict[str, Any] | None:
    normalized = dashboard_phase_key(phase)
    for item in _DASHBOARD_PHASES:
        if item["normalized_key"] == normalized or item["key"] == normalized:
            return dict(item)
    return None


def dashboard_phase_display_name(phase: Any) -> str:
    meta = dashboard_phase_meta(phase)
    if meta:
        return str(meta["display_name"])
    normalized = normalize_phase_name(phase)
    return normalized.replace("_", " ").title() if normalized else "Unknown Phase"


def is_valid_dashboard_phase(phase: Any, executable_only: bool = False) -> bool:
    meta = dashboard_phase_meta(phase)
    if not meta:
        return False
    return bool(meta["is_executable"]) if executable_only else True


def previous_dashboard_phase(phase: Any, executable_only: bool = False) -> dict[str, Any] | None:
    phases = dashboard_phase_catalog(executable_only=executable_only)
    normalized = dashboard_phase_key(phase)
    for index, item in enumerate(phases):
        if item["normalized_key"] == normalized:
            return dict(phases[index - 1]) if index > 0 else None
    return None


def next_dashboard_phase(phase: Any, executable_only: bool = False) -> dict[str, Any] | None:
    phases = dashboard_phase_catalog(executable_only=executable_only)
    normalized = dashboard_phase_key(phase)
    for index, item in enumerate(phases):
        if item["normalized_key"] == normalized:
            return dict(phases[index + 1]) if index + 1 < len(phases) else None
    return None


def dashboard_phase_index(phase: Any, executable_only: bool = False) -> int:
    phases = dashboard_phase_catalog(executable_only=executable_only)
    normalized = dashboard_phase_key(phase)
    for index, item in enumerate(phases):
        if item["normalized_key"] == normalized:
            return index
    return -1


def dashboard_phase_key(phase: Any) -> str:
    normalized = normalize_phase_name(phase)
    return _DASHBOARD_PHASE_KEY_MAP.get(normalized, normalized)


def canonical_kill_chain_label(phase_name: Any) -> str:
    normalized = normalize_phase_name(phase_name)
    if not normalized:
        return "RECONNAISSANCE"
    return _KILL_CHAIN_LABEL_MAP.get(normalized, normalized.upper())


def pentest_stage_label(phase_name: Any) -> str:
    normalized = normalize_phase_name(phase_name)
    if not normalized:
        return "planning_recon"
    return _STAGE_LABEL_MAP.get(normalized, "planning_recon")


def parse_positive_int(value: Any, fallback: int) -> int:
    try:
        parsed = int(float(value))
    except (TypeError, ValueError):
        return int(fallback)
    return max(parsed, 1)


def build_runtime_profile(overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = dict(overrides or {})
    max_retries = parse_positive_int(
        payload.get("max_retries", DEFAULT_STEP_MAX_RETRIES),
        DEFAULT_STEP_MAX_RETRIES,
    )
    retry_cooldown_seconds = parse_positive_int(
        payload.get("retry_cooldown_seconds", DEFAULT_STEP_RETRY_COOLDOWN_SECONDS),
        DEFAULT_STEP_RETRY_COOLDOWN_SECONDS,
    )
    limits = dict(DEFAULT_LEVEL_LIMITS)
    supplied_limits = payload.get("limits") if isinstance(payload.get("limits"), dict) else {}
    for key, default_value in DEFAULT_LEVEL_LIMITS.items():
        limits[key] = parse_positive_int(supplied_limits.get(key, default_value), default_value)
    return {
        "max_retries": max_retries,
        "retry_cooldown_seconds": retry_cooldown_seconds,
        "limits": limits,
    }
