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


AI RUNTIME ARCHITECTURE (IMPLEMENTATION GUIDANCE)

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
