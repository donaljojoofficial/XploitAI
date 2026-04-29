from __future__ import annotations

import json
import logging
from typing import Optional

from ai.llm.nvidia_output_analysis_adapter import NvidiaOutputAnalysisAdapter
from core.config import get_config

logger = logging.getLogger(__name__)


ACTION_FINDING_KEYS = {
    "HTTPHeaderFetch": ["server_banner", "x_powered_by", "missing_security_headers"],
    "TechnologyFingerprint": ["identified_technologies"],
    "EndpointDiscovery": ["discovered_endpoints"],
    "EndpointProbe": ["discovered_endpoints"],
    "ParameterDiscovery": ["discovered_parameters"],
    "VulnerabilityScanning": ["missing_security_headers", "exposed_paths", "suspicious_paths", "sqli_signals", "scan_completed"],
    "SQLInjectionProbe": ["sqli_signals"],
    "ExploitAttempt": ["valid_credentials", "session_cookies", "redirect_targets", "exploit_research_completed"],
    "ProofOfCompromise": ["proof_of_compromise", "proof_summary"],
}


class OutputAnalysisService:
    def __init__(self, provider: Optional[str] = None):
        requested = (provider or get_config("OUTPUT_ANALYSIS_PROVIDER") or "nvidia").lower()
        self.provider = requested
        self.adapter = NvidiaOutputAnalysisAdapter() if requested in {"auto", "nvidia", "nvidia_reasoning"} else None

    def analyze(
        self,
        action_name: str,
        stdout: str,
        stderr: str = "",
        findings: Optional[dict] = None,
    ) -> dict:
        if not self.adapter:
            return {}

        prompt = self._build_prompt(action_name, stdout, stderr, findings or {})
        payload = self.adapter.analyze(prompt)
        if not isinstance(payload, dict):
            return {}

        extracted = payload.get("findings") if isinstance(payload.get("findings"), dict) else {}
        normalized = self._sanitize_findings(action_name, extracted)
        if normalized:
            logger.info("Output analysis extracted findings for '%s': %s", action_name, normalized)
        return normalized

    def _build_prompt(self, action_name: str, stdout: str, stderr: str, findings: dict) -> str:
        allowed_keys = ACTION_FINDING_KEYS.get(action_name, [])
        return (
            "You analyze safe cyber-range command output and extract only concrete evidence.\n"
            f"Action: {action_name}\n"
            f"Allowed finding keys: {', '.join(allowed_keys) if allowed_keys else 'none'}\n"
            f"Existing findings: {json.dumps(findings, separators=(',', ':'))}\n"
            "Rules:\n"
            "- Return JSON only.\n"
            "- Do not invent evidence.\n"
            "- Ignore generic failures unless they reveal a concrete finding.\n"
            "- Use short arrays and compact strings.\n"
            "- Prefer URLs, parameter names, technologies, headers, credentials, cookies, proof paths.\n"
            'Schema: {"findings": {...}}\n'
            f"STDOUT:\n{(stdout or '')[:12000]}\n\n"
            f"STDERR:\n{(stderr or '')[:4000]}"
        )

    def _sanitize_findings(self, action_name: str, findings: dict) -> dict:
        allowed_keys = set(ACTION_FINDING_KEYS.get(action_name, []))
        if not allowed_keys:
            return {}

        cleaned = {}
        for key, value in findings.items():
            if key not in allowed_keys:
                continue
            if value in (None, "", [], {}):
                continue
            if isinstance(value, (str, int, float, bool, list, dict)):
                cleaned[key] = value
        return cleaned
