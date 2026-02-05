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


