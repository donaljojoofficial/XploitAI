## Bug Fixes
- 2026-01-30: Dashboard routing showed Django welcome page at "/" due to missing app registration and URL inclusion. Fixed by adding 'dashboard' to INSTALLED_APPS, creating dashboard.urls with a root path, and including it at the project root URL.
- 2026-01-30: Django RuntimeError indicated core.models not in INSTALLED_APPS, causing startup failure when dashboard imported models. Fixed by adding minimal core app config (apps.py, __init__.py) and registering 'core' in INSTALLED_APPS.
- 2026-01-30: Runtime error "no such table: core_attackstate" due to missing migrations for core app. FIXED by creating and applying initial migrations for 'core'.

## Infrastructure
- 2026-01-30: Added data migration to seed a deterministic initial AttackState for a fresh database. FIXED by introducing core/migrations/0002_seed_initial_attack_state.py.

DEVELOPMENT TODO LIST — XPLOITAI (PHASE 1)

TODO 1: Define core AttackState data model - [completed]
TODO 2: Define Action and ActionResult models - [completed]
TODO 3: Implement Action Registry with predefined actions - [completed]
TODO 4: Implement Policy validation engine - [completed]
TODO 5: Implement Simulation Executor - [completed]
TODO 6: Implement AI Decision Engine interface - [completed]
TODO 7: Implement Orchestration loop (state machine) - [completed]
TODO 8: Implement attack timeline model - [completed]
TODO 9: Build basic dashboard views - [completed]

RULE:
Request exactly ONE TODO at a time.

Correct usage:
> Complete TODO 1

## AI Runtime Implementation (PHASE 2)

TODO AI-1: Define AI runtime module structure
Status: COMPLETED

TODO AI-2: Define AI decision input schema (state representation)
Status: COMPLETED

TODO AI-3: Implement AI decision engine (single-step recommendation)
Status: COMPLETED

TODO AI-4: Integrate AI decision output with policy engine
Status: COMPLETED

TODO AI-5: Add logging and audit trail for AI decisions
Status: COMPLETED

TODO AI-6: Extend AI to multi-step planning (optional)
Status: COMPLETED


## AI Runtime – Advanced (PHASE 3)

TODO AI-7: Implement AI memory store for past decisions and outcomes
Status: PENDING

TODO AI-8: Integrate AI memory into decision and planning logic
Status: PENDING

TODO AI-9: Define LLM adapter interface for AI decision support
Status: PENDING

TODO AI-10: Implement Gemini/OpenAI adapter (one provider only)
Status: PENDING

TODO AI-11: Add fallback to rule-based decision engine
Status: PENDING

TODO AI-12: Define approval-required action categories
Status: PENDING

TODO AI-13: Implement approval gate before executor
Status: PENDING

TODO AI-14: Add approval decision logging
Status: PENDING

TODO UI-1: Display AI-generated plans in dashboard
Status: PENDING

TODO UI-2: Visualize plan execution state and policy outcomes
Status: PENDING

## Defender AI

TODO DEF-1: Define defender AI observation schema
Status: PENDING

TODO DEF-2: Implement defender rule-based detection engine
Status: PENDING

TODO DEF-3: Integrate defender alerts into dashboard
Status: PENDING
