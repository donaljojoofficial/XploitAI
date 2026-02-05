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
