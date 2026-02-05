# XploitAI – System Architecture (Autonomous AI Mode)

## Architectural Goal

XploitAI is an AI-orchestrated cyber range designed to demonstrate
autonomous penetration testing behavior in a controlled, isolated lab.

The system enables:
- Full AI autonomy at the decision and planning layers
- Real tool execution in an attacker VM
- Continuous AI adaptation based on results
- Defender AI observation and interruption
- Complete auditability and explainability

Autonomy is intentional, bounded, logged, and sandboxed.

---

## High-Level Architecture

[Autonomous AI Controller]
        ↓
[Safety Filter / Sandbox]
        ↓
[Execution Task Queue]
        ↓
[Executor Daemon (Attacker VM)]
        ↓
[Target VM (Vulnerable)]
        ↓
[Results + Logs + Memory]
        ↺ (feedback loop to AI)

---

## Core Architectural Principle

AI is fully autonomous in:
- Planning
- Command generation
- Retry logic
- Stop decisions

AI is NOT trusted blindly.
All execution passes through safety controls and isolation.

---

## System Layers

### 1. AI Runtime Layer (`ai/`)

Responsibilities:
- Analyze current attack state
- Generate shell commands dynamically
- Control autonomous execution loop
- Reflect on results and adapt
- Decide when to retry, re-plan, or stop

Components:
- `decision_engine.py` – high-level reasoning
- `autonomy.py` – autonomous control loop
- `command_generator.py` – AI → shell command generation
- `reflection.py` – evaluate success/failure
- `memory.py` – past attempts and outcomes
- `safety.py` – command validation & sandbox rules
- `llm/` – LLM adapters (Gemini/OpenAI/Claude)

The AI runtime MUST NOT:
- Access the OS directly
- Execute commands
- Bypass safety filters

---

### 2. Safety & Sandbox Layer

Responsibilities:
- Validate AI-generated commands
- Enforce scope limits (IP range, tools, privileges)
- Block destructive or out-of-scope behavior

Examples of blocked behavior:
- Commands targeting non-lab IPs
- Destructive filesystem operations
- Privilege abuse outside defined rules

This layer is mandatory even in full autonomy mode.

---

### 3. Execution Interface Layer (`executor/`)

Responsibilities:
- Expose APIs for external executors
- Queue approved execution tasks
- Accept execution results

This layer:
- Does NOT generate commands
- Does NOT decide what to run
- Acts as a job broker only

---

### 4. Executor Daemon (Attacker VM)

Runs on Kali Linux.

Responsibilities:
- Poll controller for tasks
- Execute commands locally
- Capture stdout/stderr
- Return results
- Retry connection if controller is unavailable

Executor:
- Has no AI logic
- Has no planning logic
- Executes exactly what it is given

---

### 5. Defender AI Layer

Responsibilities:
- Observe attacker behavior
- Detect suspicious or risky patterns
- Raise alerts
- Recommend halting or re-planning

Defender AI:
- Does NOT block execution directly
- Influences AI autonomy via alerts

---

### 6. Dashboard & Audit Layer

Responsibilities:
- Visualize AI plans and execution steps
- Show generated commands (sanitized)
- Display defender alerts
- Display stop reasons and outcomes

All actions must be replayable and explainable.

---

## Autonomy Guarantees

- AI controls the loop, not the machine
- Every action is logged
- Every command is auditable
- The lab is isolated
- Failures are recoverable
- The system can stop itself

---

## Development Rules for AI Assistants

- AI autonomy logic lives ONLY in `ai/`
- Execution logic lives ONLY in executor daemon
- Safety filters are mandatory
- No shortcuts
- All changes must be task-driven via `todo.md`



# XploitAI – Frontend & Dashboard Architecture (Phase: Observability)

## Purpose of the Frontend

The frontend dashboard is the **single source of truth** for observing,
explaining, and auditing autonomous AI behavior inside the cyber range.

It does NOT:
- Control execution directly
- Make AI decisions
- Run commands

It ONLY:
- Visualizes system state
- Reflects real backend data
- Enables human understanding and intervention

---

## Core Design Principle

Every UI element MUST map to a real backend signal.

No mock data.
No placeholders.
No inferred state.

If data does not exist in the backend, the UI must not invent it.

---

## High-Level Frontend Architecture

[ Django Backend APIs ]
          ↓
[ Dashboard Data Layer ]
          ↓
[ UI Components ]
          ↓
[ Human Observer / Approver ]

---

## Frontend Responsibilities (Strict)

### 1. AI Autonomy Visualization

The dashboard must display:
- Current AI mode (IDLE / RUNNING / PAUSED / STOPPED)
- Current autonomy cycle state
- Stop reason (if halted)
- Retry count and limits

Source of truth:
- AI autonomy controller state
- Autonomy audit logs

---

### 2. Plan & Reasoning View

The dashboard must show:
- Current AI plan (ordered steps)
- Completed vs pending steps
- Reasoning summary per step
- Memory influence indicators

Source of truth:
- AI planning data
- AI memory records
- Audit logs

---

### 3. Execution & Task Queue View

The dashboard must show:
- ExecutionTask list
- Task status (PENDING / RUNNING / DONE / FAILED)
- Action name
- Sanitized command (if applicable)
- Execution output / error

Source of truth:
- ExecutionTask model
- Executor API results

---

### 4. Defender AI View

The dashboard must show:
- Defender alerts
- Alert severity
- Alert reason
- Defender recommendations (halt / re-plan)

Source of truth:
- Defender AI outputs
- Defender audit logs

---

### 5. Timeline & Replay

The dashboard must support:
- Chronological timeline of events
- Replay of AI decisions and executions
- Clear cause–effect relationships

Source of truth:
- Unified audit log stream

---

## Frontend Technology Constraints

- Frontend uses Django templates (initially)
- JavaScript allowed for dynamic updates
- No SPA rewrite required
- Polling is acceptable (WebSockets optional later)

---

## Data Flow Rules

- Frontend NEVER mutates AI state directly
- Frontend actions (approve / halt) go through:
  Controller → Policy → AI autonomy layer
- Frontend must handle missing data gracefully

---

## Development Rules for AI Agents (Frontend)

- Do NOT invent backend fields
- Do NOT hardcode states
- Do NOT duplicate business logic in templates
- Prefer backend aggregation over frontend computation
- Each UI component must document its data source



# XploitAI – Dashboard Frontend Architecture (Template-Based Migration)

## Purpose of This Phase

This phase migrates the dashboard from backend-rendered HTML strings
to a proper Django template-based frontend to ensure:

- Accurate UI updates
- Clear separation of logic and presentation
- Reliable frontend iteration
- Agent-safe frontend development

Backend logic MUST remain unchanged.

---

## Current Problem Being Solved

The existing dashboard:
- Generates HTML directly in Python views
- Does not use Django templates
- Causes UI changes to appear inconsistent or invisible
- Prevents effective frontend iteration

This phase addresses presentation only.

---

## High-Level Frontend Architecture (After Migration)

[ Backend Views (Python Logic Only) ]
                ↓ context dict
[ Django Templates (HTML) ]
                ↓
[ Browser Rendering ]
                ↓
[ Human Observer ]

---

## Directory Structure (Required)

dashboard/
├── views.py                 # Data preparation only (NO HTML)
├── urls.py
├── templates/
│   └── dashboard/
│       ├── index.html
│       ├── attack_detail.html
│       ├── replay.html
│       └── partials/
│           ├── autonomy_status.html
│           ├── plan_steps.html
│           ├── defender_alerts.html
│           └── execution_tasks.html
├── static/
│   └── dashboard/
│       ├── css/
│       └── js/

---

## View Responsibilities (STRICT)

Dashboard views MUST:
- Query models / logs
- Prepare structured context dictionaries
- Call `render(request, template, context)`

Dashboard views MUST NOT:
- Generate HTML strings
- Contain presentation logic
- Perform formatting beyond basic serialization

---

## Template Responsibilities (STRICT)

Templates MUST:
- Render data passed from views
- Use simple conditional logic only
- Avoid business logic
- Never compute system state

---

## Migration Strategy

- Existing views are refactored incrementally
- HTML is extracted into templates
- Logic stays exactly the same
- One view at a time

---

## Development Rules for Agents

- Do NOT change backend logic
- Do NOT rename existing URLs
- Do NOT introduce new models
- Do NOT invent context fields
- Extract presentation only



📐 Architecture Update — Operational Control & Cyber Range Integration

This extends your existing architecture.
It does not weaken autonomy or safety.

1. New Architectural Concept: Operational Context

Autonomous attacks require explicit operational context:

Who is attacking?

What is the target?

Is the execution environment ready?

This context must be validated before autonomy starts.

2. Updated High-Level Architecture
[ Dashboard Control Panel ]
        ↓
[ Operational Context Manager ]   ← NEW
        ↓
[ Autonomous AI Controller ]
        ↓
[ Safety Filter ]
        ↓
[ Execution Task Queue ]
        ↓
[ Executor Daemon (Attacker VM) ]
        ↓
[ Target VM ]

3. Backend Components (NEW / EXTENDED)
A. Attacker Executor Registry (NEW)

Tracks real executor machines.

Model: AttackerExecutor

name

ip_address

status (CONNECTED / DISCONNECTED)

last_heartbeat

capabilities (optional)

Executor daemon must periodically heartbeat.

B. Target Registry (NEW)

Defines explicit, approved targets.

Model: AttackTarget

name

ip_address

operating_system

vulnerability_profile (label only)

is_active

created_at

Autonomy can only target registered, active targets.

C. Operational Context (NEW)

Defines one active attack context at a time.

Model: AttackContext

attacker_executor (FK)

target (FK)

status (READY / RUNNING / STOPPED)

started_at

stopped_at

stop_reason

This is what the dashboard controls.

D. Autonomous Controller (EXTENDED)

The controller must now:

Refuse to start without a valid AttackContext

Bind all planning/execution to that context

Stop if context becomes invalid (executor offline, target disabled)

No change to planning logic — only guardrails.

4. Executor Daemon Responsibility (REAL)

Executor daemon must:

Register itself on startup

Send heartbeat every N seconds

Refuse execution if context target ≠ local network scope

This makes attacker readiness provable.

5. Dashboard Responsibility (REAL)

Dashboard must:

Display live executor status

Display target info from DB

Allow starting autonomy only when context is READY

Disable controls otherwise

No fake buttons.