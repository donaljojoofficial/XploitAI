# XploitAI – Development TODO List

This file controls AI-assisted development.
The agent must only work on explicitly assigned TODOs.

---

## Phase 1 – Foundation (COMPLETED)

- AI planning and decision engine
- AI memory and adaptation
- Policy enforcement
- Defender agent (read-only)
- Human approval gates
- Dashboard visualization
- Execution task model
- Executor API endpoints

---

## Phase 2 – Full AI Autonomy (Style C)

### Autonomous Control

TODO AUTO-1: Implement autonomous AI control loop
Status: COMPLETED

TODO AUTO-2: Add retry, re-plan, and stop conditions
Status: COMPLETED

TODO AUTO-3: Integrate defender alerts into autonomy decisions
Status: COMPLETED

TODO AUTO-4: Add autonomy audit logging and replay support
Status: COMPLETED

---

### AI Command Generation

TODO CMD-1: Implement AI-driven shell command generator
Status: COMPLETED

TODO CMD-2: Integrate LLM reasoning into command generation
Status: COMPLETED

TODO CMD-3: Add command explanation summaries for audit logs
Status: COMPLETED

---

### Safety & Sandbox

TODO SAFE-1: Implement command safety filter
Status: COMPLETED

TODO SAFE-2: Enforce lab-only network scope
Status: COMPLETED

TODO SAFE-3: Add execution timeout and resource limits
Status: COMPLETED

---

### Execution Layer

TODO EXEC-3: Define action/command execution contract
Status: COMPLETED

TODO EXEC-4: Implement executor daemon (Kali)
Status: COMPLETED

TODO EXEC-5: Add reconnection and resilience logic
Status: COMPLETED

---

### Dashboard & Audit

---

### Defender AI (Autonomous Context)

TODO DEF-4: Allow defender to trigger AI halt or re-plan
Status: COMPLETED

TODO DEF-5: Visualize attacker vs defender interaction
Status: COMPLETED

---

## Bug Fixes

(Add bugs here. Do NOT delete previous entries.)

---

## Rules

- Only one TODO may be worked on at a time
- Mark TODO as DONE or FIXED explicitly
- Do NOT invent new TODOs
- Do NOT modify this file unless instructed



# XploitAI – Development TODO List

---

## Phase 4 – Frontend Observability & Dashboard Accuracy

This phase focuses on making the system observable,
accurate, and defensible through the dashboard.

---

### Dashboard Foundation

TODO UI-1: Audit existing dashboard views and templates
Status: COMPLETED

TODO UI-2: Map dashboard components to real backend data sources
Status: COMPLETED

---

### AI Autonomy Visualization

TODO UI-3: Display AI autonomy state (running, paused, stopped)
Status: COMPLETED

TODO UI-4: Display AI stop reasons and retry counts
Status: COMPLETED

---

### Plan & Reasoning Visualization

TODO UI-5: Render AI plan steps with status indicators
Status: COMPLETED

TODO UI-6: Display reasoning summaries per plan step
Status: COMPLETED

---


TODO UI-7: Indicate AI memory influence on decisions
Status: COMPLETED

---

### Execution & Task Queue

TODO UI-8: Display ExecutionTask queue with live status
Status: COMPLETED

TODO UI-9: Show sanitized commands and execution output
Status: COMPLETED

---

### Defender AI Visualization

TODO UI-10: Display defender alerts and severity levels
Status: COMPLETED

TODO UI-11: Visualize attacker vs defender interaction
Status: COMPLETED

---

### Timeline & Replay

TODO UI-12: Implement unified event timeline
Status: COMPLETED

TODO UI-13: Add replay view for AI decisions and executions
Status: PENDING

---

## Bug Fixes

(Add dashboard bugs here. Do NOT delete previous entries.)

---

## Rules

- Only work on one TODO at a time
- Mark TODO as DONE or FIXED explicitly
- Do NOT invent new backend fields
- Do NOT modify AI autonomy logic during this phase
