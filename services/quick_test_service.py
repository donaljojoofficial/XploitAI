import logging
import json
import re
import shlex
import threading
import time
from typing import Any

from django.utils import timezone

from core.models import Action, AttackState, AttackTimelineEvent, Command, ExecutionResult, ExecutionTask, Phase
from ai.llm.nvidia_output_analysis_adapter import NvidiaOutputAnalysisAdapter
from executor.local_executor import run_command
from executor import ssh_executor
from parser.output_parser import merge_findings, parse_output
from state.state_manager import StateManager
from services.command_template_utils import build_target_context, infer_required_tools

logger = logging.getLogger(__name__)


QUICK_ACTIONS: dict[str, dict[str, str]] = {
    "default_credentials": {
        "label": "Default credential brute force",
        "action_name": "QuickDefaultCredentialCheck",
        "description": "Try a small bounded list of common lab credentials against /login.",
    },
    "headers": {
        "label": "Header check",
        "action_name": "QuickHeaderCheck",
        "description": "Fetch response headers and flag missing common security headers.",
    },
    "paths": {
        "label": "Common path check",
        "action_name": "QuickPathCheck",
        "description": "Probe a short list of common exposed paths.",
    },
    "sqli": {
        "label": "SQLi smoke test",
        "action_name": "QuickSQLiSmoke",
        "description": "Send a small set of SQLi probes to likely login/search endpoints.",
    },
}


def selected_quick_actions(raw_actions: list[str] | None) -> list[str]:
    selected = [item for item in (raw_actions or []) if item in QUICK_ACTIONS]
    return selected or ["default_credentials", "headers", "paths"]


def quick_action_catalog() -> list[dict[str, str]]:
    return [{"key": key, **value} for key, value in QUICK_ACTIONS.items()]


class QuickTestService:
    def __init__(self, attack_state_id: int):
        self.attack_state_id = attack_state_id
        self.state_manager = StateManager(attack_state_id)

    def start(self) -> None:
        AttackState.objects.filter(id=self.attack_state_id).update(
            autonomy_status="RUNNING",
            stop_reason="Quick test started.",
        )
        thread = threading.Thread(target=self._run, daemon=True)
        thread.start()

    def ensure_review(self) -> dict[str, Any]:
        state = self.state_manager.get_attack_state()
        state_data = state.state_data if isinstance(state.state_data, dict) else {}
        existing = self._latest_quick_review(state_data)
        if existing:
            return existing
        target = state_data.get("target") or ""
        return self._store_quick_review(target)

    def _latest_quick_review(self, state_data: dict[str, Any]) -> dict[str, Any]:
        for key in ("level_history", "phase_reviews"):
            history = state_data.get(key)
            if not isinstance(history, list):
                continue
            for item in reversed(history):
                if isinstance(item, dict) and item.get("phase") == "quick_test":
                    return item
        return {}

    def _run(self) -> None:
        state = self.state_manager.get_attack_state()
        state_data = state.state_data if isinstance(state.state_data, dict) else {}
        target = state_data.get("target") or ""
        mode = state_data.get("execution_mode") or "local"
        selected = selected_quick_actions(state_data.get("quick_actions") or [])
        total = len(selected)

        try:
            for index, action_key in enumerate(selected, start=1):
                state.refresh_from_db()
                if state.autonomy_status == "STOPPED":
                    return
                action_meta = QUICK_ACTIONS[action_key]
                command = self._build_command(action_key, target)
                action = Action.objects.create(
                    attack_state=state,
                    name=action_meta["action_name"],
                    description=action_meta["description"],
                    reasoning="Operator-selected quick test action outside the phased planner.",
                    parameters={
                        "target": target,
                        "quick_action": action_key,
                        "command": command,
                    },
                    status="PENDING",
                )
                AttackTimelineEvent.objects.create(
                    attack_state=state,
                    action=action,
                    event_type="EXECUTION",
                    phase=state.current_phase or "RECONNAISSANCE",
                    message=f"Quick action {index}/{total}: {action_meta['label']}",
                    data={"command": command, "quick_action": action_key},
                )

                result = self._execute_command(state, action, command, mode)
                stdout = str(result.get("stdout") or "")
                stderr = str(result.get("stderr") or result.get("error") or "")
                returncode = int(result.get("returncode", result.get("exit_code", -1)) or 0)
                findings = self._parse_quick_output(action_meta["action_name"], stdout)
                status = "SUCCESS" if returncode == 0 else "FAILED"

                command_obj = self._command_record(action_meta["action_name"], action_meta["description"], command)
                ExecutionResult.objects.create(
                    command=command_obj,
                    attack_state=state,
                    target=target,
                    status=status,
                    stdout=stdout,
                    stderr=stderr,
                    findings=findings,
                )
                if findings:
                    self.state_manager.update_state_with_findings(findings, phase_name="quick_test")
                self._update_quick_plan_step(state, action_key, status, command, findings)
                action.status = "EXECUTED"
                action.save(update_fields=["status"])
                AttackTimelineEvent.objects.create(
                    attack_state=state,
                    action=action,
                    event_type="STATE_UPDATE",
                    phase=state.current_phase or "RECONNAISSANCE",
                    message=f"Quick action finished: {action_meta['label']} ({status})",
                    data={"findings": findings, "returncode": returncode},
                )

            review_item = self._store_quick_review(target)
            stop_reason = "Quick test completed."
            if review_item.get("review"):
                stop_reason = f"Quick test completed. AI review: {review_item.get('review')}"
            AttackState.objects.filter(id=self.attack_state_id).update(
                autonomy_status="STOPPED",
                current_phase="COMPLETED",
                stop_reason=stop_reason[:2000],
            )
        except Exception as exc:
            logger.exception("Quick test failed for AttackState %s", self.attack_state_id)
            AttackState.objects.filter(id=self.attack_state_id).update(
                autonomy_status="STOPPED",
                stop_reason=f"Quick test failed: {exc}",
            )

    def _execute_command(self, state: AttackState, action: Action, command: str, mode: str) -> dict[str, Any]:
        state_data = state.state_data if isinstance(state.state_data, dict) else {}
        if mode == "ssh":
            from core.models import AttackerExecutor

            executor = AttackerExecutor.objects.get(id=state_data.get("executor_id"))
            return ssh_executor.run_command(executor, command, timeout_seconds=0)

        if mode == "remote":
            task = ExecutionTask.objects.create(
                action_name=action.name,
                action=action,
                parameters={
                    "command": command,
                    "target": state_data.get("target") or "",
                    "reasoning": action.reasoning,
                    "required_tools": infer_required_tools(command),
                    "execution_type": "command",
                    "limits": {"timeout": 0, "max_retries": 0, "retry_cooldown_seconds": 0},
                },
                status="PENDING",
                requires_approval=False,
            )
            return self._wait_for_task(task)

        return run_command(command, timeout_seconds=0)

    def _store_quick_review(self, target: str) -> dict[str, Any]:
        state = self.state_manager.get_attack_state()
        state.refresh_from_db()
        state_data = state.state_data if isinstance(state.state_data, dict) else {}
        findings = state_data.get("findings") if isinstance(state_data.get("findings"), dict) else {}
        plan = state.current_plan if isinstance(state.current_plan, dict) else {}
        plan_steps = plan.get("steps") if isinstance(plan.get("steps"), list) else []
        result_summaries = self._quick_result_summaries(state)
        review = self._generate_quick_ai_review(target, plan_steps, result_summaries, findings)

        review_item = {
            "phase": "quick_test",
            "phase_display": "Quick Test",
            "level": {"index": 0, "kill_chain_label": "Standalone Quick Test"},
            "kill_chain_label": "Standalone Quick Test",
            "stage_label": "Quick Test",
            "next_phase": "",
            "review": review.get("summary") or "Quick test completed.",
            "findings": findings,
            "details": {
                **review,
                "phase": "quick_test",
                "target": target,
                "plan_snapshot": plan_steps,
                "results_snapshot": result_summaries,
                "current_findings": findings,
                "review_generated_at": timezone.now().isoformat(),
            },
        }

        reviews = state_data.get("phase_reviews")
        if not isinstance(reviews, list):
            reviews = []
        level_history = state_data.get("level_history")
        if not isinstance(level_history, list):
            level_history = []
        reviews.append(review_item)
        level_history.append(review_item)
        state_data["phase_reviews"] = reviews[-50:]
        state_data["level_history"] = level_history[-50:]
        state.state_data = state_data
        state.save(update_fields=["state_data"])
        self.state_manager.record_phase_review("quick_test", review_item)

        AttackTimelineEvent.objects.create(
            attack_state=state,
            event_type="STATE_UPDATE",
            phase=state.current_phase if state.current_phase in {"RECONNAISSANCE", "ENUMERATION", "EXPLOITATION", "PRIVILEGE_ESCALATION", "PROOF_OF_COMPROMISE", "COMPLETED"} else "COMPLETED",
            message="Quick test AI review stored.",
            data={"review": review_item.get("review"), "key_evidence": review.get("key_evidence") or []},
        )
        return review_item

    def _quick_result_summaries(self, state: AttackState) -> list[dict[str, Any]]:
        results = (
            ExecutionResult.objects.filter(attack_state=state, command__phase__name="quick_test")
            .select_related("command")
            .order_by("created_at")
        )
        summaries = []
        for result in results:
            summaries.append(
                {
                    "command": getattr(result.command, "name", "unknown"),
                    "status": result.status,
                    "stdout_excerpt": (result.stdout or "")[:1200],
                    "stderr_excerpt": (result.stderr or "")[:500],
                    "findings": result.findings or {},
                }
            )
        return summaries

    def _generate_quick_ai_review(
        self,
        target: str,
        plan_steps: list[dict[str, Any]],
        result_summaries: list[dict[str, Any]],
        findings: dict[str, Any],
    ) -> dict[str, Any]:
        fallback = self._fallback_quick_review(plan_steps, result_summaries, findings)
        prompt = (
            "You are reviewing a standalone quick pentest run in an authorized cyber range.\n"
            "Analyze the command outputs and findings. Be concrete and do not invent evidence.\n"
            "Return JSON only with this schema:\n"
            '{"summary":"...", "phase_objective":"...", "command_reviews":[{"command":"...", "purpose":"...", "status":"...", "outcome":"..."}], "key_evidence":["..."], "recommended_next_phase":"", "operator_notes":"..."}\n'
            "Focus especially on successful brute-force credentials, login result URLs, exposed paths, headers, and SQLi signals if present.\n"
            f"Quick test data:\n{json.dumps({'target': target, 'plan_steps': plan_steps, 'results': result_summaries, 'findings': findings}, sort_keys=True, default=str)[:14000]}"
        )
        try:
            adapter = NvidiaOutputAnalysisAdapter()
            review = adapter.analyze(prompt)
            if isinstance(review, dict):
                review.setdefault("summary", fallback["summary"])
                review.setdefault("phase_objective", fallback["phase_objective"])
                review.setdefault("command_reviews", fallback["command_reviews"])
                review.setdefault("key_evidence", fallback["key_evidence"])
                review.setdefault("recommended_next_phase", "")
                review.setdefault("operator_notes", fallback["operator_notes"])
                review["ai_generated"] = True
                review["review_provider"] = "nvidia_output_analysis"
                return review
        except Exception as exc:
            logger.warning("Quick test AI review failed: %s", exc)
        fallback["ai_generated"] = False
        fallback["review_provider"] = "fallback"
        return fallback

    def _fallback_quick_review(
        self,
        plan_steps: list[dict[str, Any]],
        result_summaries: list[dict[str, Any]],
        findings: dict[str, Any],
    ) -> dict[str, Any]:
        credentials = findings.get("valid_credentials") if isinstance(findings, dict) else None
        if isinstance(credentials, list) and credentials:
            summary = f"Quick test found {len(credentials)} successful credential set(s)."
        else:
            summary = "Quick test completed; review command outputs for successful checks and errors."
        command_reviews = []
        result_by_command = {item.get("command"): item for item in result_summaries if isinstance(item, dict)}
        for step in plan_steps:
            action_key = step.get("action_type") or ""
            quick_meta = QUICK_ACTIONS.get(action_key, {})
            command_name = quick_meta.get("action_name") or step.get("name") or action_key or "unknown"
            display_name = step.get("name") or quick_meta.get("label") or command_name
            result = result_by_command.get(command_name) or result_by_command.get(action_key) or result_by_command.get(display_name) or {}
            command_reviews.append(
                {
                    "command": display_name,
                    "purpose": step.get("description") or "",
                    "status": result.get("status") or step.get("status") or "UNKNOWN",
                    "outcome": (result.get("stdout_excerpt") or result.get("stderr_excerpt") or "")[:240],
                }
            )
        return {
            "summary": summary,
            "phase_objective": "Run selected standalone quick actions outside the phased pentest workflow.",
            "command_reviews": command_reviews,
            "key_evidence": sorted((findings or {}).keys())[:8],
            "recommended_next_phase": "",
            "operator_notes": "AI review provider was unavailable; this deterministic review is based on parsed findings.",
        }

    def _update_quick_plan_step(self, state: AttackState, action_key: str, status: str, command: str, findings: dict) -> None:
        state.refresh_from_db()
        plan = state.current_plan if isinstance(state.current_plan, dict) else {}
        steps = plan.get("steps") if isinstance(plan.get("steps"), list) else []
        for step in steps:
            if step.get("action_type") != action_key:
                continue
            step["status"] = "completed" if status == "SUCCESS" else "failed"
            step["resolved_command"] = command
            step["last_findings"] = findings or {}
            history = step.get("execution_history")
            if not isinstance(history, list):
                history = []
            history.append(
                {
                    "status": status,
                    "command": command,
                    "stdout_excerpt": self._credential_output_excerpt(findings),
                    "stderr_excerpt": "",
                    "findings": findings or {},
                    "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
            )
            step["execution_history"] = history[-10:]
            break
        state.current_plan = plan
        state.save(update_fields=["current_plan"])

    def _credential_output_excerpt(self, findings: dict | None) -> str:
        findings = findings or {}
        credentials = findings.get("valid_credentials")
        if isinstance(credentials, list) and credentials:
            lines = ["Successful credential(s):"]
            for credential in credentials:
                if not isinstance(credential, dict):
                    continue
                lines.append(
                    "path={path} username={username} password={password}".format(
                        path=credential.get("path") or "",
                        username=credential.get("username") or "",
                        password=credential.get("password") or "",
                    )
                )
            return "\n".join(lines)
        return ""

    def _wait_for_task(self, task: ExecutionTask) -> dict[str, Any]:
        while True:
            task.refresh_from_db()
            if task.status in {"COMPLETED", "FAILED", "TIMEOUT"}:
                if isinstance(task.output, dict):
                    return task.output
                return {
                    "stdout": str(task.output or ""),
                    "stderr": task.error_message or "",
                    "returncode": 0 if task.status == "COMPLETED" else 1,
                }
            time.sleep(1)

    def _command_record(self, name: str, description: str, command: str) -> Command:
        phase, _ = Phase.objects.get_or_create(
            name="quick_test",
            defaults={"description": "Standalone quick tests outside the phased pentest planner."},
        )
        command_obj, _ = Command.objects.get_or_create(
            name=name,
            defaults={"phase": phase, "description": description, "command_template": command},
        )
        changed = False
        if command_obj.phase_id != phase.id:
            command_obj.phase = phase
            changed = True
        if command_obj.command_template != command:
            command_obj.command_template = command
            changed = True
        if command_obj.description != description:
            command_obj.description = description
            changed = True
        if changed:
            command_obj.save(update_fields=["phase", "description", "command_template"])
        return command_obj

    def _build_command(self, action_key: str, target: str) -> str:
        context = build_target_context(target)
        base = shlex.quote(str(context.get("target_url") or target).rstrip("/"))
        if action_key == "default_credentials":
            return "python3 -c " + shlex.quote(self._default_credential_script(str(context.get("target_url") or target).rstrip("/")))
        if action_key == "headers":
            return f"curl -k -I --max-time 20 {base}"
        if action_key == "sqli":
            return (
                "python3 -c "
                + shlex.quote(
                    "import urllib.parse,urllib.request,urllib.error\n"
                    f"base={str(context.get('target_url') or target).rstrip('/')!r}\n"
                    "payloads=[\"' OR '1'='1\",\"' OR 1=1--\",\"admin'--\"]\n"
                    "targets=[('/login.php','POST','username'),('/login','POST','username'),('/search.php','GET','q'),('/search','GET','q')]\n"
                    "print('QUICK_SQLI_START')\n"
                    "for path,method,param in targets:\n"
                    "  for payload in payloads:\n"
                    "    try:\n"
                    "      if method=='POST':\n"
                    "        data=urllib.parse.urlencode({param:payload,'password':'test'}).encode(); req=urllib.request.Request(base+path,data=data)\n"
                    "      else:\n"
                    "        req=urllib.request.Request(base+path+'?'+urllib.parse.urlencode({param:payload}))\n"
                    "      resp=urllib.request.urlopen(req,timeout=8); body=resp.read(800).decode('utf-8','ignore').lower()\n"
                    "      if any(x in body for x in ['sql','syntax','mysql','sqlite','postgres','warning']): print('SQLI_SIGNAL: '+path+' payload='+payload)\n"
                    "      else: print('SQLI_CHECK: '+path+' payload='+payload+' status='+str(resp.status))\n"
                    "      resp.close()\n"
                    "    except urllib.error.HTTPError as e: print('SQLI_HTTP_'+str(e.code)+': '+path+' payload='+payload)\n"
                    "    except Exception as e: print('SQLI_ERROR: '+path+' '+str(e))\n"
                    "print('QUICK_SQLI_COMPLETE')\n"
                )
            )
        return (
            "python3 -c "
            + shlex.quote(
                "import urllib.request,urllib.error\n"
                f"base={str(context.get('target_url') or target).rstrip('/')!r}\n"
                "paths=['/login.php','/login','/admin','/admin/login.php','/phpinfo.php','/.env','/config.php','/backup','/robots.txt']\n"
                "print('QUICK_PATH_CHECK_START')\n"
                "for path in paths:\n"
                "  try:\n"
                "    req=urllib.request.Request(base+path,headers={'User-Agent':'XploitAI-QuickTest/1.0'},method='HEAD')\n"
                "    resp=urllib.request.urlopen(req,timeout=8); print('['+str(resp.status)+']: '+base+path); resp.close()\n"
                "  except urllib.error.HTTPError as e:\n"
                "    if e.code not in (404,410): print('['+str(e.code)+']: '+base+path)\n"
                "  except Exception as e: print('PATH_ERROR: '+path+' '+str(e))\n"
                "print('QUICK_PATH_CHECK_COMPLETE')\n"
            )
        )

    def _default_credential_script(self, target_url: str) -> str:
        return (
            "import urllib.parse,urllib.request,urllib.error,http.cookiejar\n"
            f"base={target_url!r}\n"
            "creds=[('admin','admin'),('admin','password'),('admin','123456'),('root','root'),('test','test')]\n"
            "paths=['/login.php','/login','/admin/login','/admin/login.php']\n"
            "positive=['logout','dashboard','welcome','profile','account','settings']\n"
            "negative=['login failed','invalid password','invalid username','incorrect','try again']\n"
            "print('QUICK_BRUTE_FORCE_START')\n"
            "found=False\n"
            "for path in paths:\n"
            "  if found: break\n"
            "  for user,pwd in creds:\n"
            "    jar=http.cookiejar.CookieJar(); opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))\n"
            "    data=urllib.parse.urlencode({'username':user,'password':pwd,'Login':'Login'}).encode()\n"
            "    try:\n"
            "      req=urllib.request.Request(base+path,data=data,headers={'User-Agent':'XploitAI-QuickTest/1.0','Content-Type':'application/x-www-form-urlencoded'})\n"
            "      resp=opener.open(req,timeout=10)\n"
            "      raw=resp.read(250000); body=raw.decode('utf-8','ignore'); lower=body.lower()\n"
            "      ok=any(x in lower for x in positive) and not any(x in lower for x in negative)\n"
            "      print(('AUTH_SUCCESS: ' if ok else 'AUTH_FAIL: ')+path+' user='+user+' password='+pwd)\n"
            "      if ok:\n"
            "        print('SUCCESSFUL_CREDENTIAL: path='+path+' username='+user+' password='+pwd)\n"
            "        print('SUCCESSFUL_LOGIN_URL: '+resp.geturl())\n"
            "        found=True\n"
            "        for cookie in jar:\n"
            "          print('SESSION_COOKIE: '+cookie.name+'='+cookie.value)\n"
            "        break\n"
            "      resp.close()\n"
            "    except urllib.error.HTTPError as e:\n"
            "      print('AUTH_HTTP_'+str(e.code)+': '+path+' user='+user+' password='+pwd)\n"
            "    except Exception as e:\n"
            "      print('AUTH_ERROR: '+path+' user='+user+' error='+str(e))\n"
            "if not found: print('NO_VALID_DEFAULT_CREDENTIALS')\n"
            "print('QUICK_BRUTE_FORCE_COMPLETE')\n"
        )

    def _parse_quick_output(self, action_name: str, stdout: str) -> dict:
        findings = {}
        if action_name == "QuickDefaultCredentialCheck":
            findings = parse_output("ExploitAttempt", stdout)
            findings = merge_findings(findings, self._extract_successful_credentials(stdout))
            if "QUICK_BRUTE_FORCE_COMPLETE" in (stdout or ""):
                findings["quick_bruteforce_completed"] = True
            return findings
        if action_name == "QuickSQLiSmoke":
            findings = parse_output("SQLInjectionProbe", stdout)
            if "QUICK_SQLI_COMPLETE" in (stdout or ""):
                findings["quick_sqli_completed"] = True
            return findings
        if action_name == "QuickPathCheck":
            findings = parse_output("EndpointDiscovery", stdout)
            if "QUICK_PATH_CHECK_COMPLETE" in (stdout or ""):
                findings["quick_path_check_completed"] = True
            return findings
        if action_name == "QuickHeaderCheck":
            findings = parse_output("HTTPHeaderFetch", stdout)
            if stdout:
                findings["quick_header_check_completed"] = True
            return findings
        return merge_findings(findings, {})

    def _extract_successful_credentials(self, stdout: str) -> dict:
        matches = re.findall(
            r"(?:SUCCESSFUL_CREDENTIAL:\s*path=|AUTH_SUCCESS:\s*)([^\s]+)\s+(?:username|user)=([^\s]+)\s+password=([^\r\n]+)",
            stdout or "",
        )
        if not matches:
            return {}
        credentials = []
        seen = set()
        for path, username, password in matches:
            item = (path.strip(), username.strip(), password.strip())
            if item in seen:
                continue
            seen.add(item)
            credentials.append({"path": item[0], "username": item[1], "password": item[2]})
        return {"valid_credentials": credentials} if credentials else {}
