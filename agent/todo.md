## Bug Fixes
- 2026-01-30: Dashboard routing showed Django welcome page at "/" due to missing app registration and URL inclusion. Fixed by adding 'dashboard' to INSTALLED_APPS, creating dashboard.urls with a root path, and including it at the project root URL.
- 2026-01-30: Django RuntimeError indicated core.models not in INSTALLED_APPS, causing startup failure when dashboard imported models. Fixed by adding minimal core app config (apps.py, __init__.py) and registering 'core' in INSTALLED_APPS.

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
