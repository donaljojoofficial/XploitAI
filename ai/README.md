XploitAI Runtime AI Layer

Purpose
- This package defines the structural scaffolding for the future AI runtime layer that will host the real agent logic.
- It introduces clear boundaries and responsibilities without implementing behavior.
- No external LLM SDKs or AI logic are imported or executed here.

Guiding Principles
- Structure only: placeholders, interfaces, and documentation.
- Import-safe: importing any module in this package must have no side effects.
- Compliance: follow repository coding standards, security posture, and project scope.

Module Overview
- __init__.py: Declares the ai package and exports stable type aliases for external imports.
- decision_engine.py: Placeholder entry point interface for AI decision evaluation.
- state_adapter.py: Adapters that transform Core AttackState and related domain objects into AI-readable inputs.
- memory.py: Interfaces for agent memory, storage of prior actions and outcomes.
- schemas.py: Typed data structures for inputs/outputs exchanged between AI components.

Notes
- Do not add runtime logic, network calls, or side effects.
- Do not import model SDKs or perform planning/execution. This is scaffolding only.
- Any future logic changes must preserve import-safety and adhere to security standards.