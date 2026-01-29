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
