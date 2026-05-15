from __future__ import annotations

import json
import logging
import time
from typing import Any, Optional

from django.utils import timezone

from ai.llm.base import BaseLLMAdapter
from ai.llm.task_router import TaskRouterAdapter
from core.config import get_config
from core.levels import dashboard_phase_display_name, is_valid_dashboard_phase, normalize_phase_name
from core.models import AttackState
logger = logging.getLogger(__name__)


class DashboardChatService:
    SESSION_KEY = "dashboard_chat_transcripts"
    SESSION_LIMIT = 12

    def __init__(self, request) -> None:
        self.request = request

    def ask(
        self,
        *,
        attack_id: int,
        message: str,
        phase_key: Optional[str] = None,
        include_recommendations: bool = True,
    ) -> dict[str, Any]:
        attack_state = AttackState.objects.filter(pk=attack_id, owner=self.request.user).first()
        if not attack_state:
            return {
                "answer": "",
                "selected_run": None,
                "phase": phase_key or "",
                "evidence_refs": [],
                "suggested_followups": [],
                "memory_summary_updated": False,
                "warnings": ["Selected run was not found."],
            }

        normalized_phase = normalize_phase_name(phase_key or "")
        if normalized_phase and not is_valid_dashboard_phase(normalized_phase):
            return {
                "answer": "",
                "selected_run": {"id": attack_state.id, "name": attack_state.name},
                "phase": normalized_phase,
                "evidence_refs": [],
                "suggested_followups": [],
                "memory_summary_updated": False,
                "warnings": ["Requested phase was not recognized."],
            }

        transcript = self._get_session_transcript(attack_state.id)
        context = self._build_context_snapshot(attack_state, normalized_phase or None)
        persisted_memory = self._get_persisted_memory(attack_state)

        warnings = []
        if not context["phases"] and not context["active_steps"]:
            warnings.append("This run has limited stored execution context, so the answer may be brief.")

        prompt = self._build_prompt(
            message=message,
            context=context,
            persisted_memory=persisted_memory,
            transcript=transcript,
            include_recommendations=include_recommendations,
        )

        answer = self._generate_answer(prompt)
        if not answer:
            answer = (
                "I could not get a response from the configured AI providers right now. "
                "Please review the latest run evidence and try again."
            )
            warnings.append("The AI provider did not return a response.")

        updated = self._update_memory(
            attack_state=attack_state,
            message=message,
            answer=answer,
            phase_key=normalized_phase or None,
            evidence_refs=context["evidence_refs"],
            include_recommendations=include_recommendations,
        )
        self._append_session_transcript(attack_state.id, "user", message)
        self._append_session_transcript(attack_state.id, "assistant", answer)

        return {
            "answer": answer,
            "selected_run": {
                "id": attack_state.id,
                "name": attack_state.name,
                "current_phase": attack_state.current_phase,
                "status": attack_state.autonomy_status,
            },
            "phase": normalized_phase or "",
            "evidence_refs": context["evidence_refs"],
            "suggested_followups": self._suggest_followups(context, normalized_phase or None),
            "memory_summary_updated": updated,
            "warnings": warnings,
        }

    def reset(self, attack_id: int) -> None:
        transcripts = self.request.session.get(self.SESSION_KEY, {})
        transcripts.pop(str(attack_id), None)
        self.request.session[self.SESSION_KEY] = transcripts
        self.request.session.modified = True

    def _build_context_snapshot(self, attack_state: AttackState, phase_key: Optional[str]) -> dict[str, Any]:
        from dashboard.views import _build_attack_run_history, _build_plan_view_state, _get_unified_events

        history = _build_attack_run_history(attack_state)
        plan_view = _build_plan_view_state(attack_state)
        events = _get_unified_events(attack_state)
        filtered_phases = history.get("phases", [])
        filtered_events = events[-12:]

        if phase_key:
            filtered_phases = [
                item for item in filtered_phases
                if normalize_phase_name(item.get("phase")) == phase_key
            ]
            filtered_events = [
                item for item in events
                if normalize_phase_name(((item.get("data") or {}).get("phase") or "")) == phase_key
            ][-12:]

        active_steps = []
        current_phase = normalize_phase_name((attack_state.current_plan or {}).get("phase") or attack_state.current_phase)
        if not phase_key or phase_key == current_phase:
            for step in (plan_view.get("steps") or [])[:8]:
                active_steps.append(
                    {
                        "action_type": step.get("action_type") or step.get("action") or "unknown",
                        "status": step.get("status") or "pending",
                        "rationale": step.get("rationale") or "",
                        "success_criteria": step.get("success_criteria") or "",
                        "output_excerpt": (step.get("output_excerpt") or "")[:500],
                        "attempt_count": int(step.get("attempt_count") or 0),
                    }
                )

        state_data = attack_state.state_data or {}
        latest_report = plan_view.get("last_report")
        findings = state_data.get("findings") if isinstance(state_data.get("findings"), dict) else {}
        phase_payloads = []
        evidence_refs: list[str] = []
        for phase in filtered_phases[-4:]:
            phase_payloads.append(
                {
                    "phase": phase.get("phase"),
                    "summary": phase.get("summary", {}),
                    "review": phase.get("review", ""),
                    "findings": phase.get("findings", [])[:6],
                    "outputs": [
                        {
                            "command": item.get("command"),
                            "status": item.get("status"),
                            "stdout_excerpt": (item.get("stdout_excerpt") or "")[:240],
                            "stderr_excerpt": (item.get("stderr_excerpt") or "")[:160],
                        }
                        for item in (phase.get("outputs") or [])[:6]
                    ],
                }
            )
            evidence_refs.append(f"phase:{normalize_phase_name(phase.get('phase'))}")

        if active_steps:
            evidence_refs.append("current_plan")
        if latest_report:
            evidence_refs.append("latest_report")
        if findings:
            evidence_refs.append("findings")
        if filtered_events:
            evidence_refs.append("timeline")

        return {
            "attack": {
                "id": attack_state.id,
                "name": attack_state.name,
                "current_phase": attack_state.current_phase,
                "current_phase_display": dashboard_phase_display_name(attack_state.current_phase),
                "autonomy_status": attack_state.autonomy_status,
                "stop_reason": attack_state.stop_reason or "",
                "target": state_data.get("target") or "",
            },
            "phase_focus": phase_key or "",
            "phases": phase_payloads,
            "active_steps": active_steps,
            "findings": findings,
            "execution_history": (state_data.get("execution_history") or [])[-8:],
            "latest_report": {
                "generated_at": latest_report.get("generated_at"),
                "status": latest_report.get("status"),
                "executive_summary": ((latest_report.get("payload") or {}).get("executive_summary") if isinstance(latest_report.get("payload"), dict) else ""),
            } if isinstance(latest_report, dict) else {},
            "recent_events": [
                {
                    "source": item.get("source"),
                    "type": item.get("type"),
                    "desc": item.get("desc"),
                    "phase": ((item.get("data") or {}).get("phase") or ""),
                }
                for item in filtered_events
            ],
            "evidence_refs": evidence_refs,
        }

    def _build_prompt(
        self,
        *,
        message: str,
        context: dict[str, Any],
        persisted_memory: dict[str, Any],
        transcript: list[dict[str, str]],
        include_recommendations: bool,
    ) -> str:
        recent_transcript = transcript[-6:]
        instructions = [
            "You are an operator-facing security assistant inside XploitAI.",
            "Use only the provided run evidence when describing what happened.",
            "If you give general guidance beyond the evidence, label it clearly as general guidance.",
            "Do not claim actions were executed unless the evidence shows that.",
            "Keep the answer concise, clear, and grounded in the run context.",
        ]
        if include_recommendations:
            instructions.append(
                "Recommend only advisory next steps that fit the current run state; do not imply execution or approval already happened."
            )

        payload = {
            "instructions": instructions,
            "persisted_memory": persisted_memory,
            "recent_transcript": recent_transcript,
            "run_context": context,
            "operator_question": message,
        }
        return json.dumps(payload, indent=2, default=str)

    def _generate_answer(self, prompt: str) -> str:
        provider = (get_config("DEFAULT_LLM_PROVIDER", "auto") or "auto").strip().lower()
        adapter = self._chat_adapter(provider)
        if not adapter:
            return ""
        try:
            if hasattr(adapter, "generate_for_task"):
                return adapter.generate_for_task(prompt, task_key="chat.explain_run") or ""
            return adapter.generate(prompt) or ""
        except Exception as exc:
            logger.warning("DashboardChatService provider call failed: %s", exc)
            return ""

    def _chat_adapter(self, provider: str) -> Optional[BaseLLMAdapter]:
        adapters_by_name = self._discover_adapters(provider)
        if not adapters_by_name:
            return None
        routes = {
            "chat": ["nvidia", "groq", "openai", "gemini", "lmstudio", "local"],
            "chat.explain_run": ["nvidia", "groq", "openai", "gemini", "lmstudio", "local"],
            "generate": ["nvidia", "groq", "openai", "gemini", "lmstudio", "local"],
        }
        return TaskRouterAdapter(adapters_by_name, task_routes=routes)

    def _discover_adapters(self, provider: str) -> dict[str, BaseLLMAdapter]:
        requested = (provider or "auto").lower()
        requested_names: set[str]
        if requested in {"auto", "fallback"}:
            requested_names = {"nvidia", "groq", "openai", "gemini", "lmstudio"}
        elif requested == "hybrid":
            requested_names = {"nvidia", "groq"}
        elif requested == "local":
            requested_names = set()
        else:
            requested_names = {requested}

        adapters_by_name: dict[str, BaseLLMAdapter] = {}
        if "gemini" in requested_names:
            try:
                from ai.llm.gemini import GeminiAdapter
                adapter = GeminiAdapter()
                if adapter._client:
                    adapters_by_name["gemini"] = adapter
            except Exception:
                pass
        if "openai" in requested_names:
            try:
                from ai.llm.openai_adapter import OpenAIAdapter
                adapters_by_name["openai"] = OpenAIAdapter()
            except Exception:
                pass
        if "groq" in requested_names:
            try:
                from ai.llm.groq_adapter import GroqAdapter
                adapter = GroqAdapter()
                if adapter._client:
                    adapters_by_name["groq"] = adapter
            except Exception:
                pass
        if "nvidia" in requested_names:
            try:
                from ai.llm.nvidia_adapter import NvidiaAdapter
                adapter = NvidiaAdapter()
                if adapter._available:
                    adapters_by_name["nvidia"] = adapter
            except Exception:
                pass
        if "lmstudio" in requested_names:
            try:
                from ai.llm.lmstudio_adapter import LMStudioAdapter
                adapter = LMStudioAdapter()
                if adapter._available:
                    adapters_by_name["lmstudio"] = adapter
            except Exception:
                pass

        from ai.llm.local_rule_engine import LocalRuleEngine
        adapters_by_name["local"] = LocalRuleEngine()
        return adapters_by_name

    def _get_persisted_memory(self, attack_state: AttackState) -> dict[str, Any]:
        state_data = attack_state.state_data or {}
        return {
            "summary": state_data.get("chat_memory_summary") or "",
            "topics": state_data.get("chat_last_topics") or [],
            "last_recommendations": state_data.get("chat_last_recommendations") or [],
            "last_question_at": state_data.get("chat_last_question_at") or None,
        }

    def _update_memory(
        self,
        *,
        attack_state: AttackState,
        message: str,
        answer: str,
        phase_key: Optional[str],
        evidence_refs: list[str],
        include_recommendations: bool,
    ) -> bool:
        if not isinstance(attack_state.state_data, dict):
            attack_state.state_data = {}
        state_data = attack_state.state_data
        topics = state_data.get("chat_last_topics")
        if not isinstance(topics, list):
            topics = []
        topic = phase_key or normalize_phase_name(attack_state.current_phase)
        if topic:
            topics.append(topic)
        topics = topics[-5:]

        state_data["chat_last_topics"] = topics
        state_data["chat_last_question_at"] = timezone.now().isoformat()
        summary = (
            f"Last question: {message[:180]}\n"
            f"Phase focus: {phase_key or normalize_phase_name(attack_state.current_phase)}\n"
            f"Evidence used: {', '.join(evidence_refs[:6]) or 'none'}\n"
            f"Last answer summary: {answer[:400]}"
        )
        state_data["chat_memory_summary"] = summary
        if include_recommendations:
            state_data["chat_last_recommendations"] = self._extract_recommendation_lines(answer)
        attack_state.save(update_fields=["state_data"])
        return True

    def _extract_recommendation_lines(self, answer: str) -> list[str]:
        lines = [line.strip("- ").strip() for line in answer.splitlines() if line.strip()]
        prioritized = [line for line in lines if any(token in line.lower() for token in ("recommend", "next", "review", "inspect", "retry", "open", "generate", "verify"))]
        return prioritized[:4] or lines[:3]

    def _get_session_transcript(self, attack_id: int) -> list[dict[str, str]]:
        transcripts = self.request.session.get(self.SESSION_KEY, {})
        items = transcripts.get(str(attack_id), [])
        return items if isinstance(items, list) else []

    def _append_session_transcript(self, attack_id: int, role: str, content: str) -> None:
        transcripts = self.request.session.get(self.SESSION_KEY, {})
        if not isinstance(transcripts, dict):
            transcripts = {}
        items = transcripts.get(str(attack_id), [])
        if not isinstance(items, list):
            items = []
        items.append({"role": role, "content": content[:4000], "timestamp": int(time.time())})
        transcripts[str(attack_id)] = items[-self.SESSION_LIMIT:]
        self.request.session[self.SESSION_KEY] = transcripts
        self.request.session.modified = True

    def _suggest_followups(self, context: dict[str, Any], phase_key: Optional[str]) -> list[str]:
        suggestions = []
        if phase_key:
            suggestions.append(f"Explain why the {dashboard_phase_display_name(phase_key)} phase behaved this way")
        suggestions.extend(
            [
                "Summarize the latest execution",
                "What should I do next?",
                "Explain the latest report",
                "Which failure matters most right now?",
            ]
        )
        if not context.get("latest_report"):
            suggestions.append("Should I generate a report now?")
        return suggestions[:5]
