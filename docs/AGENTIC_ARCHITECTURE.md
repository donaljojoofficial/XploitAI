# XploitAI - Agentic AI Architecture

XploitAI now uses an agentic control-plane architecture. The system is modeled
as cooperating agents with explicit state, policy, execution, memory, and review
boundaries instead of a single opaque autonomy loop.

## Runtime Topology

```text
[Human Operator]
        |
        v
[Agent Console]
        |
        v
[Orchestrator Agent]
        |
        v
[Planner Agent] -> [Policy Guard] -> [Executor Agent]
        ^                 |                 |
        |                 v                 v
[Reviewer Agent] <- [Memory Agent] <- [Results / Evidence]
```

## Agent Responsibilities

- Orchestrator Agent: owns lifecycle, stop conditions, retries, and phase handoff.
- Planner Agent: creates bounded plans from scope, findings, tools, and history.
- Policy Guard: enforces safety, approval, and scope before execution.
- Executor Agent: dispatches approved commands through local, SSH, or daemon paths.
- Memory Agent: persists findings, outputs, execution history, reviews, and reports.
- Reviewer Agent: explains outcomes and recommends operator-safe next steps.

## Control Loop

```text
Sense -> Plan -> Guard -> Act -> Learn -> Review -> Sense
```

The loop is intentionally gated. AI can propose and adapt, but execution remains
bounded by registered targets, executor readiness, policy checks, and human
approval where required.

## Code Contract

- `ai/agentic_architecture.py` is the shared architecture contract for UI and
  runtime metadata.
- `ai/planner.py`, `ai/autonomy.py`, and `ai/llm/task_router.py` implement the
  planner, controller, and model-routing agents.
- `policy/`, `executor/`, `services/`, and `state/` remain separate boundaries.
- Dashboard templates render architecture state only from backend context.
