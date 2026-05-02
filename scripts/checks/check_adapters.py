"""
Adapter Output Test Script
==========================
Tests selected LLM adapters to check if they return output.

Adapters tested:
  - GeminiAdapter (requires GOOGLE_API_KEY or GEMINI_API_KEY)
  - GroqAdapter   (requires GROQ_API_KEY)
  - NvidiaAdapter (requires NVIDIA_API_KEY or a model-specific NVIDIA_API_KEY_<MODEL>)

Run from the XploitAI directory:
    python scripts/checks/check_adapters.py
"""

import io
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

# Force UTF-8 stdout so symbols render reliably on Windows terminals.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
else:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Load local .env so standalone runs pick up API keys like manage.py does.
load_dotenv(PROJECT_ROOT / ".env")

logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s [%(name)s] %(message)s",
)

from ai.schemas import ActionResultSummary, Decision, DecisionInput, KnownService, PastActionSummary

SAMPLE_INPUT = DecisionInput(
    phase="RECONNAISSANCE",
    known_services=[
        KnownService(
            name="dvwa",
            endpoint="http://localhost:80",
            protocol="http",
        )
    ],
    past_actions=[
        PastActionSummary(
            action_type="PassiveRecon",
            parameters={"target_domain": "localhost"},
            phase="RECONNAISSANCE",
        )
    ],
    last_result=ActionResultSummary(
        success=True,
        output_summary="Passive recon completed.",
        raw_output="HTTP/1.1 200 OK",
    ),
    available_commands=[
        {"name": "HTTPHeaderFetch", "description": "Fetch HTTP headers from target"},
        {"name": "TechnologyFingerprint", "description": "Fingerprint web technologies"},
    ],
    findings={"recon": {"http_headers": {"Server": "Apache"}}},
)

SAMPLE_DECISION = Decision(
    action_type="HTTPHeaderFetch",
    parameters={"target_url": "http://localhost:80"},
    rationale="Fetching HTTP headers to identify server technology.",
)

SIMPLE_PROMPT = "Say hello in one sentence."

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def ok(msg):
    print(f"  {GREEN}[PASS] {msg}{RESET}")


def fail(msg):
    print(f"  {RED}[FAIL] {msg}{RESET}")


def warn(msg):
    print(f"  {YELLOW}[SKIP] {msg}{RESET}")


results = {}


def record(adapter_name, test_name, passed, skipped=False, detail=""):
    result = results.setdefault(adapter_name, {"passed": 0, "failed": 0, "skipped": 0})
    suffix = f": {detail}" if detail else ""
    if skipped:
        result["skipped"] += 1
        warn(f"{test_name}{suffix}")
    elif passed:
        result["passed"] += 1
        ok(f"{test_name}{suffix}")
    else:
        result["failed"] += 1
        fail(f"{test_name}{suffix}")


def check_adapter(name, adapter, skip_reason=None):
    print(f"\n{BOLD}{CYAN}{'-' * 60}{RESET}")
    print(f"{BOLD}  Adapter: {name}{RESET}")
    if skip_reason:
        print(f"  {YELLOW}SKIPPED - {skip_reason}{RESET}")
        results[name] = {"passed": 0, "failed": 0, "skipped": 6}
        return
    print("-" * 60)

    try:
        out = adapter.generate(SIMPLE_PROMPT)
        record(name, "generate()", out is not None, detail=repr(str(out)[:80]) if out else "returned None")
    except Exception as e:
        record(name, "generate()", False, detail=f"exception: {e}")

    try:
        decision = adapter.get_recommendation(SAMPLE_INPUT)
        passed = decision is not None and hasattr(decision, "action_type")
        detail = f"action_type={decision.action_type!r}" if passed else "returned None"
        record(name, "get_recommendation()", passed, detail=detail)
    except Exception as e:
        record(name, "get_recommendation()", False, detail=f"exception: {e}")

    try:
        plan = adapter.get_plan(SAMPLE_INPUT)
        passed = plan is not None and hasattr(plan, "steps") and len(plan.steps) > 0
        detail = f"{len(plan.steps)} step(s)" if passed else "returned None or empty"
        record(name, "get_plan()", passed, detail=detail)
    except Exception as e:
        record(name, "get_plan()", False, detail=f"exception: {e}")

    try:
        explanation = adapter.explain_decision(SAMPLE_DECISION, SAMPLE_INPUT)
        passed = explanation is not None and len(str(explanation).strip()) > 0
        detail = repr(str(explanation)[:80]) if passed else "returned None or empty"
        record(name, "explain_decision()", passed, detail=detail)
    except Exception as e:
        record(name, "explain_decision()", False, detail=f"exception: {e}")

    try:
        chunks = list(adapter.generate_stream(SIMPLE_PROMPT))
        passed = len(chunks) > 0 and any(chunk for chunk in chunks)
        detail = f"{len(chunks)} chunk(s), first={repr(chunks[0][:40])}" if passed else "no chunks yielded"
        record(name, "generate_stream()", passed, detail=detail)
    except Exception as e:
        record(name, "generate_stream()", False, detail=f"exception: {e}")

    try:
        chunks = list(adapter.get_attack_narrative(SAMPLE_INPUT))
        passed = len(chunks) > 0 and any(chunk for chunk in chunks)
        detail = f"{len(chunks)} chunk(s)" if passed else "no chunks yielded"
        record(name, "get_attack_narrative()", passed, detail=detail)
    except Exception as e:
        record(name, "get_attack_narrative()", False, detail=f"exception: {e}")


def quota_skip_reason(adapter):
    if getattr(adapter, "_quota_exhausted", False):
        return "API quota exhausted"

    get_last_error = getattr(adapter, "get_last_error", None)
    if callable(get_last_error):
        last_error = get_last_error() or {}
        error_type = str(last_error.get("type") or "").lower()
        message = str(last_error.get("message") or "").lower()
        if error_type == "insufficient_quota" or "exceeded your current quota" in message:
            return "API quota exhausted"

    return None


def main():
    print(f"\n{BOLD}{'=' * 60}")
    print("  XploitAI - Adapter Output Test")
    print(f"{'=' * 60}{RESET}")

    try:
        from ai.llm.gemini import GeminiAdapter

        adapter = GeminiAdapter()
        skip = None
        if not adapter.api_key:
            skip = "GOOGLE_API_KEY / GEMINI_API_KEY not set"
        elif not adapter._client:
            skip = "Gemini client failed to initialise"
        check_adapter("GeminiAdapter", adapter, skip_reason=skip)
        quota_skip = quota_skip_reason(adapter)
        if quota_skip:
            results["GeminiAdapter"] = {"passed": 0, "failed": 0, "skipped": 6}
            print(f"  {YELLOW}NOTE - {quota_skip}{RESET}")
    except Exception as e:
        print(f"\n{RED}Failed to import/init GeminiAdapter: {e}{RESET}")

    try:
        from ai.llm.groq_adapter import GroqAdapter

        adapter = GroqAdapter()
        skip = None
        if not adapter.api_key:
            skip = "GROQ_API_KEY not set"
        elif not adapter._client:
            skip = "Groq client failed to initialise"
        check_adapter("GroqAdapter", adapter, skip_reason=skip)
    except Exception as e:
        print(f"\n{RED}Failed to import/init GroqAdapter: {e}{RESET}")

    try:
        from ai.llm.nvidia_adapter import NvidiaAdapter

        adapter = NvidiaAdapter()
        skip = None
        if not adapter.api_key:
            skip = "NVIDIA_API_KEY or model-specific NVIDIA_API_KEY_<MODEL> not set"
        elif not adapter._available:
            skip = "NVIDIA adapter is unavailable"
        check_adapter("NvidiaAdapter", adapter, skip_reason=skip)
    except Exception as e:
        print(f"\n{RED}Failed to import/init NvidiaAdapter: {e}{RESET}")

    print(f"\n{BOLD}{'=' * 60}")
    print("  SUMMARY")
    print(f"{'=' * 60}{RESET}")

    total_pass = total_fail = total_skip = 0
    for adapter_name, counts in results.items():
        passed = counts["passed"]
        failed = counts["failed"]
        skipped = counts["skipped"]
        total_pass += passed
        total_fail += failed
        total_skip += skipped
        status_color = GREEN if failed == 0 and skipped == 0 else (YELLOW if failed == 0 else RED)
        print(
            f"  {status_color}{BOLD}{adapter_name:<20}{RESET} "
            f"{GREEN}pass={passed}{RESET} "
            f"{RED}fail={failed}{RESET} "
            f"{YELLOW}skip={skipped}{RESET}"
        )

    print(f"\n  {BOLD}Total -> pass={total_pass}  fail={total_fail}  skip={total_skip}{RESET}")
    print(f"{'=' * 60}\n")

    sys.exit(1 if total_fail > 0 else 0)


if __name__ == "__main__":
    main()
