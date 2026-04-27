from __future__ import annotations

import time
from typing import Any

from core.models import AttackState, ExecutionResult


class AttackReportService:
    def __init__(self, attack_state: AttackState):
        self.attack_state = attack_state

    def _latest_results(self) -> list[ExecutionResult]:
        return list(
            ExecutionResult.objects.filter(attack_state=self.attack_state)
            .select_related("command")
            .order_by("created_at")
        )

    def _build_timeline(self, results: list[ExecutionResult]) -> list[dict[str, Any]]:
        timeline: list[dict[str, Any]] = []
        for result in results:
            timeline.append(
                {
                    "timestamp": result.created_at.isoformat(),
                    "command": getattr(result.command, "name", "unknown"),
                    "status": result.status,
                    "stdout_excerpt": (result.stdout or "")[:500],
                    "stderr_excerpt": (result.stderr or "")[:240],
                    "findings": result.findings or {},
                }
            )
        return timeline

    def _build_script_section(self) -> list[dict[str, Any]]:
        state_data = self.attack_state.state_data or {}
        artifacts = state_data.get("script_artifacts")
        if not isinstance(artifacts, list):
            return []
        return artifacts

    def _build_report_payload(self) -> dict[str, Any]:
        state_data = self.attack_state.state_data or {}
        findings = state_data.get("findings") or {}
        level_history = state_data.get("level_history") or state_data.get("phase_reviews") or []
        results = self._latest_results()

        executive_summary = (
            f"Run '{self.attack_state.name}' completed with status {self.attack_state.autonomy_status}. "
            f"Collected {len(findings)} finding key(s) across {len(level_history)} reviewed level(s)."
        )

        remediation = [
            "Patch vulnerable services and dependencies identified in findings.",
            "Harden authentication and remove weak/default credentials.",
            "Apply least-privilege controls and monitor suspicious post-exploitation behavior.",
            "Add detections for discovered exploit and payload execution patterns.",
        ]

        return {
            "attack_id": self.attack_state.id,
            "attack_name": self.attack_state.name,
            "generated_at": time.time(),
            "executive_summary": executive_summary,
            "technical_timeline": self._build_timeline(results),
            "commands_run": [
                {
                    "name": getattr(item.command, "name", "unknown"),
                    "status": item.status,
                }
                for item in results
            ],
            "script_artifacts": self._build_script_section(),
            "findings": findings,
            "proof_evidence": findings.get("proof_of_compromise") or findings.get("proof_summary") or [],
            "remediation_recommendations": remediation,
            "level_reviews": level_history,
        }

    def generate_report(self) -> dict[str, Any]:
        payload = self._build_report_payload()
        artifact = {
            "id": f"report-{self.attack_state.id}-{int(payload['generated_at'] * 1000)}",
            "generated_at": payload["generated_at"],
            "status": "generated",
            "payload": payload,
        }

        if not isinstance(self.attack_state.state_data, dict):
            self.attack_state.state_data = {}
        reports = self.attack_state.state_data.get("report_artifacts")
        if not isinstance(reports, list):
            reports = []
        reports.append(artifact)
        self.attack_state.state_data["report_artifacts"] = reports[-20:]
        self.attack_state.state_data["last_report_at"] = payload["generated_at"]
        self.attack_state.state_data["last_report_status"] = "generated"
        self.attack_state.save(update_fields=["state_data"])
        return artifact

    def latest_report(self) -> dict[str, Any] | None:
        state_data = self.attack_state.state_data or {}
        reports = state_data.get("report_artifacts")
        if not isinstance(reports, list) or not reports:
            return None
        return reports[-1]
