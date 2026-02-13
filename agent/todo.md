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
Status: COMPLETED

---

## Bug Fixes

(Add dashboard bugs here. Do NOT delete previous entries.)

---

## Rules

- Only work on one TODO at a time
- Mark TODO as DONE or FIXED explicitly
- Do NOT invent new backend fields
- Do NOT modify AI autonomy logic during this phase


## Phase 5 – Dashboard Frontend Migration (Template-Based)

This phase migrates the dashboard from inline HTML generation
to Django templates to ensure accurate frontend updates.

---

### Migration Foundation

TODO UI-MIG-1: Create dashboard template structure
Status: COMPLETED

TODO UI-MIG-2: Migrate dashboard index view to template
Status: COMPLETED

TODO UI-MIG-3: Migrate attack detail view to template
Status: COMPLETED

---

### Component Extraction

TODO UI-MIG-4: Extract autonomy status into template partial
Status: COMPLETED

TODO UI-MIG-5: Extract AI plan steps into template partial
Status: COMPLETED

TODO UI-MIG-6: Extract defender alerts into template partial
Status: COMPLETED

TODO UI-MIG-7: Extract execution task view into template partial
Status: COMPLETED

---

### Validation & Cleanup

TODO UI-MIG-8: Remove inline HTML generation from views
Status: COMPLETED

TODO UI-MIG-9: Verify all UI updates reflect immediately in browser
Status: PENDING

---

## Rules

- Migrate ONE view or component per TODO
- Mark each TODO explicitly DONE
- No logic refactors allowed
- Presentation changes only



Phase 6 – Operational Control & Cyber Range Binding
Attacker Executor (Backend)

TODO OPS-1: Create AttackerExecutor model
Status: COMPLETED

TODO OPS-2: Implement executor heartbeat API
Status: COMPLETED

TODO OPS-3: Register executor daemon with controller
Status: COMPLETED

Target Management (Backend)

TODO OPS-4: Create AttackTarget model
Status: COMPLETED

TODO OPS-5: Add admin or seed configuration for targets
Status: COMPLETED

Attack Context Management (Backend)

TODO OPS-6: Create AttackContext model
Status: COMPLETED

TODO OPS-7: Bind autonomy controller to active AttackContext
Status: COMPLETED

TODO OPS-8: Enforce context validation before autonomy start
Status: COMPLETED


Dashboard Control Panel (Frontend)

TODO UI-CTRL-1: Display attacker executor status (live heartbeat)
Status: COMPLETED

TODO UI-CTRL-2: Display configured target system information
Status: COMPLETED

TODO UI-CTRL-3: Implement Start Autonomous Attack (real backend trigger)
Status: COMPLETED

TODO UI-CTRL-4: Disable start if executor offline or no target selected
Status: COMPLETED

---


Safety & Failure Handling

TODO OPS-9: Auto-stop autonomy if executor disconnects
Status: COMPLETED

TODO OPS-10: Log context-level start/stop reasons
Status: COMPLETED

---

##

Rules (Non-Negotiable)

Autonomy MUST NOT start without a valid AttackContext

Executor MUST heartbeat or be considered offline

Target MUST be explicitly registered

UI controls must reflect backend truth only



BUG FIXES:
- BUG-EXEC-1: Create executor API views - DONE
- BUG-EXEC-2: Register executor API URLs - DONE
- BUG-EXEC-3: Include executor API routes at project level - DONE
- BUG-EXEC-4: Verify executor endpoints return JSON - DONE
- BUG-AI-1: AI ignores active plan during execution - FIXED
- BUG-AI-2: Autonomy loop stops immediately due to stale heartbeat in simulation - FIXED
- BUG-AI-3: approve_plan race condition and context reactivation failure - FIXED
- BUG-AI-4: _parse_plan returns SimpleNamespace instead of PlanStep - FIXED




# DEVELOPMENT TODO LIST — XploitAI (Working-First Mode)

==================================================
PHASE 1 — MAKE IT WORK (CURRENT)
==================================================

TODO CORE-1:
Ensure AI generates at least one action for any active target. - COMPLETED

TODO CORE-2:
Ensure planner loop runs when autonomy is started. - COMPLETED

TODO CORE-3:
Ensure generated actions create executable tasks. - COMPLETED

TODO CORE-4:
Ensure executor successfully runs commands and returns output. - COMPLETED

==================================================
PHASE 2 — WEB ATTACK FLOW
==================================================

TODO WEB-1:
Support URL-based targets instead of IP-only targets. - COMPLETED

TODO WEB-2:
Add basic web recon actions: - COMPLETED
- HTTPHeaderFetch
- TechnologyFingerprint 
- EndpointDiscovery

TODO WEB-3:
Map web actions to executable commands (curl, nikto, etc). - COMPLETED

==================================================
PHASE 3 — FEEDBACK LOOP
==================================================

TODO FB-1:
Store execution output visibly in dashboard.

TODO FB-2:
Pass previous results into next AI planning cycle. - COMPLETED

TODO FB-3:
Allow multi-step autonomy until stop condition. - COMPLETED

==================================================
PHASE 4 — STABILIZATION
==================================================

TODO STAB-1:
Add basic error handling for failed commands.

TODO STAB-2:
Prevent infinite execution loops.

TODO STAB-3:
Add minimal logging for debugging autonomy.

==================================================
PHASE 5 — HARDENING (LATER)
==================================================

TODO HARD-1:
Introduce strict action → command policies.

TODO HARD-2:
Implement human approval gates.

TODO HARD-3:
Add audit logging and enforcement.

==================================================
PHASE 6 — PRESENTATION & REVIEW
==================================================

TODO DEMO-1:
Prepare repeatable demo scenario.

TODO DEMO-2:
Explain AI vs fallback decisions.

TODO DEMO-3:
Document safety boundaries and limitations.
