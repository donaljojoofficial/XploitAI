import json
import logging
import os
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from core.models import Action, ActionResult, AttackState
from core.levels import normalize_phase_name

logger = logging.getLogger(__name__)


def _deep_merge(existing: dict, incoming: dict) -> dict:
    merged = deepcopy(existing or {})
    for key, value in (incoming or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = deepcopy(value)
    return merged


class JsonStateStore:
    PHASE_BUCKETS = ("recon", "scanning", "exploitation")
    PHASE_BUCKET_MAP = {
        "recon": "recon",
        "reconnaissance": "recon",
        "information_gathering": "recon",
        "discovery": "scanning",
        "enumeration": "scanning",
        "vulnerability_analysis": "scanning",
        "scanning": "scanning",
        "exploitation": "exploitation",
        "privilege_escalation": "exploitation",
        "post_exploitation": "exploitation",
        "proof_of_compromise": "exploitation",
        "completed": "exploitation",
    }

    def __init__(self, attack_state_id: int, state_dir: str | Path | None = None):
        self.attack_state_id = attack_state_id
        configured_dir = state_dir or getattr(settings, "XPLOITAI_STATE_DIR", None)
        self.state_dir = Path(configured_dir or (settings.BASE_DIR / "state" / "runtime"))
        self.path = self.state_dir / f"attack_state_{attack_state_id}.json"

    def phase_bucket(self, phase_name: Any) -> str:
        return self.PHASE_BUCKET_MAP.get(normalize_phase_name(phase_name), "scanning")

    def load(self) -> dict:
        if not self.path.exists():
            return self._new_document()
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Could not read local state file %s: %s", self.path, exc)
            return self._new_document()
        return self._normalize_document(payload)

    def save(self, payload: dict) -> dict:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        normalized = self._normalize_document(payload)
        normalized["updated_at"] = timezone.now().isoformat()
        fd, tmp_name = tempfile.mkstemp(prefix=f".{self.path.stem}.", suffix=".tmp", dir=str(self.state_dir))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(normalized, handle, indent=2, sort_keys=True, default=str)
                handle.write("\n")
            os.replace(tmp_name, self.path)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
        return normalized

    def sync_from_attack_state(self, attack_state: AttackState) -> dict:
        payload = self.load()
        state_data = attack_state.state_data if isinstance(attack_state.state_data, dict) else {}
        payload["attack_state_id"] = attack_state.id
        payload["attack_name"] = attack_state.name
        payload["current_phase"] = attack_state.current_phase
        payload["target"] = state_data.get("target") or payload.get("target")
        payload["completed_commands"] = state_data.get("completed_commands", payload.get("completed_commands", []))
        payload["findings"] = _deep_merge(payload.get("findings", {}), state_data.get("findings", {}))
        return self.save(payload)

    def merge_findings(self, findings: dict, phase_name: Any = None) -> dict:
        payload = self.load()
        if findings:
            payload["findings"] = _deep_merge(payload.get("findings", {}), findings)
            bucket = self.phase_bucket(phase_name or payload.get("current_phase"))
            phase_data = payload["phase_outputs"].setdefault(bucket, self._new_phase_bucket())
            phase_data["findings"] = _deep_merge(phase_data.get("findings", {}), findings)
        return self.save(payload)

    def record_phase_output(
        self,
        phase_name: Any,
        *,
        action_name: str,
        status: str,
        command: str = "",
        command_id: int | None = None,
        target: str = "",
        stdout: str = "",
        stderr: str = "",
        findings: dict | None = None,
        exit_code: int | None = None,
        metadata: dict | None = None,
    ) -> dict:
        payload = self.load()
        bucket = self.phase_bucket(phase_name)
        phase_data = payload["phase_outputs"].setdefault(bucket, self._new_phase_bucket())
        entry = {
            "phase": normalize_phase_name(phase_name),
            "bucket": bucket,
            "action_name": action_name,
            "command_id": command_id,
            "command": command,
            "target": target,
            "status": status,
            "exit_code": exit_code,
            "stdout": stdout or "",
            "stderr": stderr or "",
            "findings": findings or {},
            "metadata": metadata or {},
            "recorded_at": timezone.now().isoformat(),
        }
        phase_data.setdefault("outputs", []).append(entry)
        phase_data["last_action"] = action_name
        phase_data["last_status"] = status
        phase_data["updated_at"] = entry["recorded_at"]
        if findings:
            payload["findings"] = _deep_merge(payload.get("findings", {}), findings)
            phase_data["findings"] = _deep_merge(phase_data.get("findings", {}), findings)
        return self.save(payload)

    def record_phase_review(self, phase_name: Any, review: dict) -> dict:
        payload = self.load()
        bucket = self.phase_bucket(phase_name)
        phase_data = payload["phase_outputs"].setdefault(bucket, self._new_phase_bucket())
        phase_data.setdefault("reviews", []).append(review or {})
        phase_data["updated_at"] = timezone.now().isoformat()
        return self.save(payload)

    def _new_document(self) -> dict:
        now = timezone.now().isoformat()
        return {
            "schema_version": 1,
            "attack_state_id": self.attack_state_id,
            "attack_name": "",
            "target": "",
            "current_phase": "",
            "findings": {},
            "completed_commands": [],
            "phase_outputs": {bucket: self._new_phase_bucket() for bucket in self.PHASE_BUCKETS},
            "created_at": now,
            "updated_at": now,
        }

    def _new_phase_bucket(self) -> dict:
        return {"findings": {}, "outputs": [], "reviews": [], "last_action": "", "last_status": "", "updated_at": ""}

    def _normalize_document(self, payload: dict) -> dict:
        normalized = self._new_document()
        if isinstance(payload, dict):
            normalized.update(payload)
        if not isinstance(normalized.get("findings"), dict):
            normalized["findings"] = {}
        if not isinstance(normalized.get("completed_commands"), list):
            normalized["completed_commands"] = []
        if not isinstance(normalized.get("phase_outputs"), dict):
            normalized["phase_outputs"] = {}
        for bucket in self.PHASE_BUCKETS:
            phase_data = normalized["phase_outputs"].get(bucket)
            base = self._new_phase_bucket()
            if isinstance(phase_data, dict):
                base.update(phase_data)
            if not isinstance(base.get("outputs"), list):
                base["outputs"] = []
            if not isinstance(base.get("reviews"), list):
                base["reviews"] = []
            if not isinstance(base.get("findings"), dict):
                base["findings"] = {}
            normalized["phase_outputs"][bucket] = base
        return normalized


class StateManager:
    """
    Manages reading and writing the attack state to the database,
    acting as an abstraction layer over the Django models.
    """

    def __init__(self, attack_state_id: int):
        self.attack_state_id = attack_state_id
        self.json_store = JsonStateStore(attack_state_id=attack_state_id)

    def get_attack_state(self) -> AttackState:
        """Retrieves the full AttackState object."""
        return AttackState.objects.get(id=self.attack_state_id)

    def get_current_state_for_planner(self) -> dict:
        """Constructs the simplified state dictionary for the AI planner."""
        state_obj = self.get_attack_state()
        if not state_obj.state_data:
            state_obj.state_data = {}
        local_state = self.json_store.sync_from_attack_state(state_obj)

        target_ref = state_obj.state_data.get("target")
        if not target_ref:
            target_ref = (
                state_obj.state_data.get("planner_context", {})
                .get("targets", [{}])[0]
                .get("primary_ref", "unknown")
            )

        # Prefer command IDs from state_data to avoid exposing raw command templates.
        completed_commands = state_obj.state_data.get("completed_commands", [])
        if not isinstance(completed_commands, list):
            completed_commands = []

        # Backward compatibility: if state_data has no completed_commands,
        # reconstruct from ExecutionResult records which have the command FK.
        if not completed_commands:
            from core.models import ExecutionResult
            completed_commands = list(
                ExecutionResult.objects.filter(
                    attack_state=state_obj,
                    status__in=["SUCCESS", "FAILED"],  # both count as done
                )
                .exclude(command=None)
                .values_list("command_id", flat=True)
                .distinct()
            )
            if completed_commands:
                # Persist back so future calls are fast
                state_obj.state_data["completed_commands"] = list(completed_commands)
                state_obj.save(update_fields=["state_data"])
                local_state = self.json_store.sync_from_attack_state(state_obj)

        return {
            "target": target_ref,
            "current_phase": state_obj.current_phase,
            "completed_commands": completed_commands,
            "findings": _deep_merge(local_state.get("findings", {}), state_obj.state_data.get("findings", {})),
            "phase_outputs": local_state.get("phase_outputs", {}),
            "local_state_file": str(self.json_store.path),
        }

    def get_available_commands(self, phase_name: str):
        """Returns Command queryset for phase excluding already completed IDs."""
        from core.models import Command, Phase

        # Normalize phase name to lowercase for database lookup
        normalized_phase = phase_name.lower() if phase_name else ""

        try:
            phase = Phase.objects.get(name__iexact=normalized_phase)
        except Phase.DoesNotExist:
            logger.warning(f"Phase not found: {phase_name} (normalized: {normalized_phase})")
            return Command.objects.none()

        state = self.get_attack_state()
        completed = state.state_data.get("completed_commands", []) or []
        return Command.objects.filter(phase=phase).exclude(id__in=completed)

    @transaction.atomic
    def add_completed_command(self, command_id: int):
        state = self.get_attack_state()
        if not state.state_data or not isinstance(state.state_data, dict):
            state.state_data = {}
        completed = state.state_data.get("completed_commands", [])
        if not isinstance(completed, list):
            completed = []
        if command_id not in completed:
            completed.append(command_id)
        state.state_data["completed_commands"] = completed
        state.state_data["local_state_file"] = str(self.json_store.path)
        state.save(update_fields=["state_data", "updated_at"])
        self.json_store.sync_from_attack_state(state)

    @transaction.atomic
    def update_state_with_findings(self, findings: dict, phase_name: str | None = None):
        """Merges new findings into the state_data JSONB field."""
        if not findings:
            return

        state = self.get_attack_state()
        if not isinstance(state.state_data, dict):
            state.state_data = {}
        if "findings" not in state.state_data:
            state.state_data["findings"] = {}

        state.state_data["findings"] = _deep_merge(state.state_data["findings"], findings)
        state.state_data["local_state_file"] = str(self.json_store.path)
        state.save(update_fields=["state_data"])
        self.json_store.merge_findings(findings, phase_name or state.current_phase)

    def record_phase_output(
        self,
        phase_name: str,
        *,
        action_name: str,
        status: str,
        command: str = "",
        command_id: int | None = None,
        target: str = "",
        stdout: str = "",
        stderr: str = "",
        findings: dict | None = None,
        exit_code: int | None = None,
        metadata: dict | None = None,
    ) -> dict:
        state = self.get_attack_state()
        if not isinstance(state.state_data, dict):
            state.state_data = {}
        state.state_data["local_state_file"] = str(self.json_store.path)
        state.save(update_fields=["state_data"])
        self.json_store.sync_from_attack_state(state)
        return self.json_store.record_phase_output(
            phase_name or state.current_phase,
            action_name=action_name,
            status=status,
            command=command,
            command_id=command_id,
            target=target,
            stdout=stdout,
            stderr=stderr,
            findings=findings or {},
            exit_code=exit_code,
            metadata=metadata or {},
        )

    def record_phase_review(self, phase_name: str, review: dict) -> dict:
        return self.json_store.record_phase_review(phase_name, review)

    @transaction.atomic
    def record_action(self, name: str, params: dict, result: dict, reasoning: str) -> Action:
        """Records a completed or failed action and its result."""
        state = self.get_attack_state()
        status = "COMPLETED" if result.get("returncode") == 0 else "FAILED"

        action = Action.objects.create(attack_state=state, name=name, parameters=params, reasoning=reasoning, status=status)
        ActionResult.objects.create(action=action, success=(status == "COMPLETED"), output=result, log_message=result.get("stderr") or f"Action {status}")

        # Keep state_data aligned with the completed action sequence
        if not state.state_data or not isinstance(state.state_data, dict):
            state.state_data = {}
        state.state_data.setdefault("completed_actions", [])
        state.state_data["completed_actions"].append(name)
        state.state_data["local_state_file"] = str(self.json_store.path)
        state.save(update_fields=["state_data"])
        self.json_store.sync_from_attack_state(state)

        return action
