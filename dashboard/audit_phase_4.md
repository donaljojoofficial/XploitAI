diff --git a/dashboard/audit_phase_4.md b/dashboard/audit_phase_4.md
new file mode 100644
index 0000000..e5b3c21
--- /dev/null
+++ b/dashboard/audit_phase_4.md
@@ -0,0 +1,63 @@
+# XploitAI Dashboard Audit (Phase 4)
+
+**Task:** TODO UI-1
+**Date:** 2026-05-XX
+**Reviewer:** AI Agent
+**Scope:** Data Model vs. UI Requirements Gap Analysis
+
+## 1. Executive Summary
+This audit assesses the readiness of the backend to support the Phase 4 Observability Dashboard.
+**Key Finding:** While the core domain models (`Action`, `AttackState`) are solid, the **AI Autonomy State** is currently in-memory only. The Dashboard cannot accurately display if the AI is "Running" or "Stopped" without schema changes.
+
+## 2. Data Source Availability Audit
+
+### A. AI Autonomy Visualization
+* **Requirement:** Display AI mode (IDLE / RUNNING / STOPPED), Stop Reason, and Retry Count.
+* **Current Backend:**
+    * `AutonomousController` (in `ai/autonomy.py`) tracks `self.running` and `self.step_count` in memory.
+    * `AttackState` (in `core/models.py`) only tracks `current_phase` (Kill Chain).
+* **Gap:** **CRITICAL**. The Dashboard (Django View) cannot access the memory of the `AutonomousController` daemon.
+* **Recommendation:** Add `autonomy_status` (Enum) and `stop_reason` (Text) fields to the `AttackState` model.
+
+### B. Plan & Reasoning View
+* **Requirement:** Display the AI's plan and the *reasoning* behind specific actions.
+* **Current Backend:**
+    * `Action` model has `description` and `parameters`.
+    * `DecisionEngine` generates proposals, but the specific "Reasoning" (LLM explanation) is not explicitly stored in a dedicated field on the `Action` model.
+* **Gap:** **MODERATE**. Users can see *what* is happening, but not *why*.
+* **Recommendation:** Add a `reasoning` TextField to the `Action` model.
+
+### C. Execution & Task Queue
+* **Requirement:** Show real-time execution logs, status, and link them to the high-level plan.
+* **Current Backend:**
+    * `ExecutionTask` exists with `status`, `output`, and `command`.
+    * Linkage to `Action` is currently implicit via JSON: `parameters['_action_id']`.
+* **Gap:** **MODERATE**. Lack of a true `ForeignKey` prevents efficient "Plan -> Execution" visualization (e.g., `action.execution_task`).
+* **Recommendation:** Add an explicit `ForeignKey` from `ExecutionTask` to `Action`.
+
+### D. Defender AI View
+* **Requirement:** Display alerts and severity.
+* **Current Backend:**
+    * `DefenderAlert` is imported in `ai/autonomy.py` but was not visible in the provided `core/models.py` context.
+* **Gap:** **VERIFICATION NEEDED**. Confirm `DefenderAlert` model exists and is migrated.
+
+## 3. Dashboard Component Readiness
+
+| Component | Backend Source | Status | Action Required |
+|-----------|---------------|--------|-----------------|
+| **Status Widget** | `AttackState` | **Partial** | Needs `autonomy_status` field. |
+| **Timeline** | `AttackTimelineEvent` | **Ready** | None. |
+| **Action Log** | `Action` | **Ready** | None. |
+| **Terminal** | `ExecutionTask` | **Partial** | Needs `ForeignKey` to `Action`. |
+
+## 4. Next Steps (for TODO UI-2)
+
+Before implementing UI templates, the following backend adjustments are required to ensure data accuracy:
+
+1.  **Schema Update:** Add `autonomy_status` and `stop_reason` to `AttackState`.
+2.  **Schema Update:** Add `action` ForeignKey to `ExecutionTask`.
+3.  **Schema Update:** Ensure `Action` has a `reasoning` field.
+4.  **Verification:** Confirm `DefenderAlert` model availability.
+
+Once these fields exist, the Dashboard views can be mapped to real data sources.
