from __future__ import annotations

import base64
import hashlib
import time
from typing import Any


def is_script_step(step: dict | None) -> bool:
    data = step or {}
    execution_type = str(data.get("execution_type") or "").strip().lower()
    return execution_type == "script"


def build_script_artifact(step: dict | None, action_name: str, command_id: int | None = None) -> dict[str, Any]:
    payload = step or {}
    script_content = str(payload.get("script_content") or "")
    script_language = str(payload.get("script_language") or "python").strip().lower() or "python"
    digest = hashlib.sha256(script_content.encode("utf-8")).hexdigest()
    created_at = time.time()
    artifact_id = f"script-{action_name.lower()}-{int(created_at * 1000)}"
    return {
        "id": artifact_id,
        "type": "generated_script",
        "action_type": action_name,
        "language": script_language,
        "sha256": digest,
        "size_bytes": len(script_content.encode("utf-8")),
        "created_at": created_at,
        "command_id": command_id,
        "content": script_content,
    }


def build_remote_script_command(script_content: str, script_language: str = "python") -> str:
    language = (script_language or "python").strip().lower()
    content = script_content or ""
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")

    if language == "bash":
        return (
            "python3 -c \"import base64,tempfile,subprocess,os;"
            f"data=base64.b64decode('{encoded}').decode('utf-8');"
            "f=tempfile.NamedTemporaryFile('w',suffix='.sh',delete=False);"
            "f.write(data);f.close();"
            "res=subprocess.run(['bash',f.name],capture_output=True,text=True);"
            "print(res.stdout, end='');"
            "print(res.stderr, end='');"
            "os.remove(f.name);"
            "raise SystemExit(res.returncode)\" || python -c \"import base64,tempfile,subprocess,os;"
            f"data=base64.b64decode('{encoded}').decode('utf-8');"
            "f=tempfile.NamedTemporaryFile('w',suffix='.sh',delete=False);"
            "f.write(data);f.close();"
            "res=subprocess.run(['bash',f.name],capture_output=True,text=True);"
            "print(res.stdout, end='');"
            "print(res.stderr, end='');"
            "os.remove(f.name);"
            "raise SystemExit(res.returncode)\""
        )

    return (
        "python3 -c \"import base64,tempfile,subprocess,os,sys;"
        f"data=base64.b64decode('{encoded}').decode('utf-8');"
        "f=tempfile.NamedTemporaryFile('w',suffix='.py',delete=False);"
        "f.write(data);f.close();"
        "res=subprocess.run([sys.executable,f.name],capture_output=True,text=True);"
        "print(res.stdout, end='');"
        "print(res.stderr, end='');"
        "os.remove(f.name);"
        "raise SystemExit(res.returncode)\" || python -c \"import base64,tempfile,subprocess,os,sys;"
        f"data=base64.b64decode('{encoded}').decode('utf-8');"
        "f=tempfile.NamedTemporaryFile('w',suffix='.py',delete=False);"
        "f.write(data);f.close();"
        "res=subprocess.run([sys.executable,f.name],capture_output=True,text=True);"
        "print(res.stdout, end='');"
        "print(res.stderr, end='');"
        "os.remove(f.name);"
        "raise SystemExit(res.returncode)\""
    )


def append_script_artifact(state_data: dict[str, Any], artifact: dict[str, Any]) -> None:
    artifacts = state_data.get("script_artifacts")
    if not isinstance(artifacts, list):
        artifacts = []
    artifacts.append(artifact)
    state_data["script_artifacts"] = artifacts[-50:]
