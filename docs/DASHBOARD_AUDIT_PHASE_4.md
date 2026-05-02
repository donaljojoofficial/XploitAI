# XploitAI Dashboard Audit (Phase 4)

**Task:** TODO UI-1  
**Date:** 2026-05-XX  
**Reviewer:** AI Agent  
**Scope:** Data Model vs. UI Requirements Gap Analysis

## 1. Executive Summary

This audit assesses the readiness of the backend to support the Phase 4
Observability Dashboard.

**Key finding:** While the core domain models (`Action`, `AttackState`) are
solid, the AI autonomy state is currently in-memory only. The dashboard cannot
accurately display whether the AI is running or stopped without schema changes.

## 2. Data Source Availability Audit

### A. AI Autonomy Visualization

**Requirement:** Display AI mode, stop reason, and retry count.

**Current backend:**

- `AutonomousController` in `ai/autonomy.py` tracks `self.running` and
  `self.step_count` in memory.
- `AttackState` in `core/models.py` only tracks `current_phase`.

**Gap:** Critical. The dashboard cannot access the memory of the
`AutonomousController` daemon.

**Recommendation:** Add `autonomy_status` and `stop_reason` fields to the
`AttackState` model.

### B. Plan And Reasoning View

**Requirement:** Display the AI plan and the reasoning behind specific actions.

**Current backend:**

- `Action` has `description` and `parameters`.
- `DecisionEngine` generates proposals, but the LLM explanation is not
  explicitly stored in a dedicated `Action` field.

**Gap:** Moderate. Users can see what is happening, but not why.

**Recommendation:** Add a `reasoning` text field to the `Action` model.

### C. Execution And Task Queue

**Requirement:** Show real-time execution logs, status, and links to the
high-level plan.

**Current backend:**

- `ExecutionTask` exists with `status`, `output`, and command-related data.
- Linkage to `Action` is implicit through JSON parameters.

**Gap:** Moderate. Lack of a true `ForeignKey` prevents efficient plan to
execution visualization.

**Recommendation:** Add an explicit `ForeignKey` from `ExecutionTask` to
`Action`.

### D. Defender AI View

**Requirement:** Display alerts and severity.

**Current backend:**

- `DefenderAlert` is imported in `ai/autonomy.py`, but was not visible in the
  provided `core/models.py` context at audit time.

**Gap:** Verification needed. Confirm the `DefenderAlert` model exists and is
migrated.

## 3. Dashboard Component Readiness

| Component | Backend Source | Status | Action Required |
| --- | --- | --- | --- |
| Status widget | `AttackState` | Partial | Needs `autonomy_status` field. |
| Timeline | `AttackTimelineEvent` | Ready | None. |
| Action log | `Action` | Ready | None. |
| Terminal | `ExecutionTask` | Partial | Needs `ForeignKey` to `Action`. |

## 4. Next Steps

Before implementing UI templates, the following backend adjustments are required
to ensure data accuracy:

1. Add `autonomy_status` and `stop_reason` to `AttackState`.
2. Add an `action` foreign key to `ExecutionTask`.
3. Ensure `Action` has a `reasoning` field.
4. Confirm `DefenderAlert` model availability.

Once these fields exist, the dashboard views can be mapped to real data sources.
