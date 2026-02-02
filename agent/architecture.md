SYSTEM ARCHITECTURE — XPLOITAI (PHASE 1)

PHASE 1 IS A SIMULATION SYSTEM, NOT A REAL ATTACK SYSTEM.

High-Level Flow:

Dashboard
  ↓
Orchestration Core
  ↓
AI Agent (Decision Engine)
  ↓
Policy Engine
  ↓
Action Registry
  ↓
Simulation Executor
  ↓
Attack State (In-Memory / DB)

STRICT RESPONSIBILITY BOUNDARIES:

agent/
- AI prompts
- Reasoning
- Action ranking
- NO execution logic

policy/
- Validate action ordering
- Enforce kill-chain rules
- Reject invalid transitions

actions/
- Atomic attack action definitions
- Preconditions and postconditions
- No execution logic

executor/
- Simulation-only executor
- Produces mock outcomes
- Updates attack state

core/
- Domain models
- State machine
- Orchestration loop

dashboard/
- Visualization only
- No decision logic
- No execution logic

DO NOT:
- Execute commands anywhere
- Bypass policy validation
- Access executor directly from agent


AI RUNTIME ARCHITECTURE (IMPLEMENTATION GUIDANCE)(PHASE 2)

The AI implementation in XploitAI is part of the runtime system,
not the development agent configuration.

The AI runtime layer is responsible for:
- Analyzing the current attack state
- Proposing next actions or action plans
- Providing reasoning for decisions

The AI runtime layer MUST NOT:
- Execute commands
- Access the operating system
- Bypass the policy engine
- Directly invoke the executor

High-level AI runtime flow:

[AttackState]
      ↓
[AI Decision Engine]
      ↓
[Policy Engine]
      ↓
[Executor (Simulation / Real)]
      ↓
[State Update]



🔧 Phase-3 Architecture Update — AI-Driven XploitAI
Purpose of Phase-3

Phase-3 introduces real AI-driven behavior into XploitAI while preserving the system’s core guarantees:

Deterministic execution

Policy authority

Auditability

Human control

The AI in Phase-3 is advisory and planning-oriented, not autonomous execution.

High-Level Runtime Architecture (Phase-3)
┌──────────────────────────┐
│   Attack State (DB)      │
└─────────────▲────────────┘
              │
┌─────────────┴────────────┐
│  AI Runtime Layer        │
│  - Decision Engine       │
│  - Planning Logic        │
│  - Memory & Context      │
│  - (Optional) LLM Adapter│
└─────────────▲────────────┘
              │
┌─────────────┴────────────┐
│     Policy Engine        │
│  - Action validation     │
│  - Safety rules          │
│  - Approval requirements │
└─────────────▲────────────┘
              │
┌─────────────┴────────────┐
│  Human Approval Gate     │  (Conditional)
└─────────────▲────────────┘
              │
┌─────────────┴────────────┐
│   Executor Layer         │
│  - Simulation / Real     │
└─────────────▲────────────┘
              │
┌─────────────┴────────────┐
│  Audit Logs & Dashboard  │
└──────────────────────────┘

AI Runtime Layer (Phase-3)
Responsibilities

The AI Runtime Layer is responsible for:

Interpreting the current attack state

Generating single-step or bounded multi-step plans

Adapting recommendations based on past outcomes

Providing reasoning for each recommendation

Explicit Non-Responsibilities

The AI Runtime Layer MUST NOT:

Execute actions

Call the executor directly

Bypass the policy engine

Modify system state directly

Run autonomous execution loops

AI Runtime Module Structure
ai/
├── decision_engine.py    # Core AI decision & planning logic
├── state_adapter.py      # Converts AttackState → AI input
├── memory.py             # Tracks past actions & outcomes
├── schemas.py            # AI input/output schemas
├── llm/                  # Optional AI API adapters
│   ├── base.py
│   ├── gemini.py
│   ├── openai.py
│   └── claude.py
└── README.md

AI Decision Flow (Phase-3)

Current AttackState is retrieved

State is converted into AI-readable schema

AI Decision Engine evaluates:

Current phase

Known information

Past outcomes (memory)

AI proposes:

One action OR

A bounded, ordered plan

Proposal is sent to Policy Engine

Policy Engine:

Approves or rejects

Flags actions requiring human approval

Approved actions proceed to execution

Results are logged and stored in memory

AI Memory & Learning (Phase-3)
Scope

AI memory in Phase-3 is behavioral memory, not model training.

Tracked information includes:

Previously attempted actions

Success/failure outcomes

Failure reasons

Confidence decay

Retry limits

Constraints

Memory influences recommendations only

Memory does NOT modify rules or policies

Memory is auditable and resettable

LLM Integration (Optional, Phase-3)

LLM providers (Gemini, OpenAI, Claude) are integrated via adapters.

Design Rules

LLMs are advisors, not decision authorities

Rule-based logic remains the default fallback

LLM output must conform to internal schemas

LLM failure must never break the system

Allowed LLM Usage

Action ranking

Plan suggestions

Explanation generation

Human Approval Gates (Phase-3)

Certain high-risk actions require explicit human approval.

Examples:

Privilege escalation

Lateral movement

Data collection

Final compromise steps

Approval Flow
AI → Policy → Approval Gate → Executor


Approval decisions are logged

Rejected actions terminate or re-plan

Defender Agent (Future-Ready)

Phase-3 architecture allows for a Defender AI, operating in parallel:

Observes shared system state

Detects suspicious behavior

Proposes defensive responses

Does NOT execute countermeasures autonomously

This remains read-only and advisory in Phase-3.

Key Architectural Guarantees (Phase-3)

AI never executes actions directly

Policy engine is always authoritative

Execution is one step at a time

Every decision is logged

Human control is preserved

Behavior is explainable and replayable

Development Guidance for AI Assistants

When implementing Phase-3 features:

AI logic must live only in ai/

No AI code in views, executor, or policy

All new behavior must be introduced via TODOs

Incremental, auditable changes only
