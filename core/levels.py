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

_STAGE_LABEL_MAP = {
    "reconnaissance": "planning_recon",
    "discovery": "scanning",
    "vulnerability_analysis": "scanning",
    "exploitation": "exploitation",
    "post_exploitation": "maintaining_access_payload",
    "proof_of_compromise": "proof_of_compromise",
    "completed": "proof_of_compromise",
}


def normalize_phase_name(phase: Any) -> str:
    return str(phase or "").strip().lower().replace(" ", "_")


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
