# XploitAI

**AI-assisted cyber range orchestration for controlled penetration testing
simulation, execution, reporting, and training.**

XploitAI is a Django-based control plane for authorized security labs. It
connects AI planning, policy validation, execution routing, state tracking,
defender observations, and dashboard visualization into one auditable workflow.

> XploitAI is for controlled education, research, and lab environments only.
> Do not use it against systems you do not own or have explicit permission to
> test.

## 1. Overview

### 1.1 At A Glance

| Area | Details |
| --- | --- |
| Application | Django web app and API control plane |
| Primary use | Authorized cyber range simulation and lab execution |
| Database | SQLite for local development |
| AI layer | Planner, decision engine, command generator, LLM adapters, local fallback |
| Execution layer | Simulation, local, SSH, and daemon-oriented execution paths |
| Dashboard | Auth, targets, executors, attack runs, phase reviews, command logs, reports, replay |
| Safety model | Registered targets, explicit executors, policy checks, command safety, auditable tasks |
| Tests | AI, dashboard, services, parser, state, and root regression tests |

### 1.2 Why It Exists

AI-assisted security tooling needs strong boundaries. XploitAI is built around
the principle that AI may propose, explain, and plan, but the application must
validate, execute, persist, and expose what happened.

### 1.3 Current Capabilities

- Multi-provider AI planning and routing with a local rule-based fallback.
- Policy and command-safety helpers before execution.
- Registered attacker executors and approved attack targets.
- Database-backed attack state, action history, task queue, command results,
  timeline events, and defender alerts.
- Dashboard workflows for operator supervision, run history, approvals, phase
  reviews, reports, replay, command logs, executor management, target
  management, and configuration.
- Simulation, local, SSH, and executor-daemon execution paths.

## 2. System Design

### 2.1 Architecture Flow

```text
Operator / Dashboard
        |
        v
Django views and APIs
        |
        v
Core models, phase catalog, state, and orchestration
        |
        v
AI planner, decision engine, and command generator
        |
        v
Policy, approval, command safety, and template validation
        |
        v
Execution service, executor API, or executor daemon
        |
        v
Simulation, local, SSH, or remote lab executor
        |
        v
Parser, state manager, reports, timeline, and dashboard
```

### 2.2 Design Principles

| Principle | Meaning |
| --- | --- |
| AI proposes | The AI layer produces plans, decisions, explanations, and command candidates. |
| Policy validates | Actions and commands pass through policy, approval, and safety checks. |
| Executors act | Execution is routed through explicit services, APIs, SSH, local runners, or simulators. |
| State records | Results, findings, timeline events, and stop reasons are persisted for review. |
| Dashboard explains | Operators can inspect plans, commands, phases, alerts, reports, and replay data. |

### 2.3 Safety Boundaries

- Targets must be registered before autonomous runs.
- Executor machines are modeled separately from targets.
- Execution tasks are persisted and tracked.
- Policy and command safety helpers validate actions before execution.
- Dashboard views expose state, plans, commands, findings, alerts, and stop
  reasons.
- Real tool use must remain inside an isolated cyber range.

## 3. Repository Structure

### 3.1 Top-Level Layout

```text
.
|-- actions/                 # Registered action definitions and action graphs
|-- agent/                   # Architecture, scope, rules, TODOs, and decision shim
|-- ai/                      # AI runtime, planners, adapters, prompts, schemas, safety
|-- core/                    # Models, admin, migrations, phases, orchestration, commands
|-- dashboard/               # Web UI, auth, forms, templates, views, API endpoints, tests
|-- docs/                    # Historical fix notes and project documentation
|-- executor/                # Executor API, daemon, contract, local/SSH/simulation runners
|-- parser/                  # Command output parsing and findings extraction
|-- policy/                  # Policy engine and approval rules
|-- scripts/                 # Manual checks and maintenance scripts
|-- services/                # Execution, reporting, quick test, preflight, command utilities
|-- state/                   # JSON-backed runtime state storage and merge helpers
|-- xploitai/                # Django settings, root URL routing, ASGI/WSGI entry points
|-- manage.py                # Django management entry point
|-- requirements.txt         # Python dependencies
|-- ai_config.json           # Default LLM provider/model configuration
`-- .env.example             # Environment variable template
```

### 3.2 Layer Map

| Layer | Main paths | Responsibility |
| --- | --- | --- |
| Interface | `dashboard/`, `xploitai/urls.py` | Web UI, auth, routing, operator workflows, and APIs. |
| Domain | `core/` | Database models, phases, runtime limits, orchestration, and admin. |
| Intelligence | `ai/`, `agent/` | Planning, decisions, prompts, provider adapters, memory, and assistant guidance. |
| Safety | `policy/`, `ai/safety.py`, `services/command_template_utils.py` | Policy validation, approvals, target-aware command rendering, and unsafe-pattern checks. |
| Execution | `executor/`, `services/execution_service.py`, `services/remote_execution_service.py`, `services/ssh_execution_service.py` | Simulation, local, SSH, daemon, task polling, and result submission. |
| Interpretation | `parser/`, `state/`, `services/reporting_service.py` | Output parsing, state merging, findings, reports, and timeline support. |
| Checks | `scripts/checks/` | Manual adapter, workflow, executor selection, and integration-loop checks. |
| Maintenance | `scripts/maintenance/`, `docs/` | Database repair helpers and historical implementation notes. |
| Tests | `ai/tests/`, `dashboard/tests/`, `services/tests/`, `parser/tests/`, `state/tests/` | Unit, integration, and regression coverage. |

### 3.3 Important Files

| Path | Purpose |
| --- | --- |
| `core/models.py` | Primary database schema for attacks, actions, commands, results, targets, executors, contexts, timeline events, execution tasks, and defender alerts. |
| `dashboard/views.py` | Main attack lifecycle, history, reports, phase details, approvals, retries, stop/resume, quick tests, configuration, and LLM status views. |
| `ai/planner.py` | AI planning and fallback planning behavior. |
| `ai/decision_engine.py` | Provider selection and decision engine facade. |
| `ai/command_generator.py` | Command generation objects and helpers. |
| `ai/audit_advisor.py` | Legacy audit-focused AI advisor retained outside the project root. |
| `actions/predefined.py` | Whitelisted action definitions, expected postconditions, lookup, and validation. |
| `services/command_template_utils.py` | Command splitting, rendering, placeholder handling, target context, tool inference, and unsafe-pattern checks. |
| `executor/api_views.py` | Executor heartbeat, task polling, and result reporting endpoints. |
| `executor/daemon.py` | Executor daemon that polls the controller and reports results. |
| `parser/output_parser.py` | Converts command output into structured findings, success signals, and completion evidence. |
| `state/state_manager.py` | Runtime JSON state storage and database-backed state merge behavior. |
| `scripts/checks/` | Manual project checks that are intentionally not named as pytest test files. |
| `scripts/maintenance/direct_fix.py` | Database maintenance helper for command template repair. |
| `docs/EXECUTOR_FIX_SUMMARY.md` | Historical executor timeout/result endpoint fix summary. |
| `docs/DASHBOARD_AUDIT_PHASE_4.md` | Historical dashboard observability audit. |
| `ai_config.json` | Default model/provider configuration. |
| `.env.example` | Local environment template. |

## 4. Getting Started

### 4.1 Requirements

- Python 3.12 recommended.
- SQLite for local development.
- Optional provider credentials depending on the AI backend you use.
- Optional SSH access to a lab attacker machine for SSH executor mode.

### 4.2 Install

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` with the provider keys and settings you plan to use.

### 4.3 Initialize

```powershell
python manage.py migrate
python manage.py seed_phases_and_commands
python manage.py seed_targets
python manage.py createsuperuser
```

### 4.4 Run

```powershell
python manage.py runserver
```

Open:

```text
http://127.0.0.1:8000/
```

Development email uses Django's console backend, so activation and password
reset messages are printed in the terminal.

## 5. Configuration

### 5.1 Environment Variables

Start with `.env.example`.

| Variable | Purpose |
| --- | --- |
| `DJANGO_SECRET_KEY` | Django secret key for local configuration. |
| `DJANGO_DEBUG` | Development debug flag. |
| `GEMINI_API_KEY` | Gemini provider key. |
| `NVIDIA_API_KEY` | NVIDIA provider key. |
| `NVIDIA_MODEL` | Default NVIDIA model. |
| `NVIDIA_TIMEOUT_SECONDS` | Request timeout for NVIDIA calls. |
| `OUTPUT_ANALYSIS_PROVIDER` | Provider used for output analysis. |
| `OUTPUT_ANALYSIS_MODEL` | Output analysis model name. |
| `OUTPUT_ANALYSIS_TIMEOUT_SECONDS` | Timeout for output analysis calls. |

### 5.2 Model Defaults

Provider and model defaults can be adjusted in `ai_config.json`.

## 6. Operations

### 6.1 Main Routes

| Route | Purpose |
| --- | --- |
| `/` | Dashboard index. |
| `/register/`, `/login/`, `/logout/`, `/profile/` | Authentication and profile flow. |
| `/history/` | Attack and test history. |
| `/assistant/` | Dashboard assistant. |
| `/start/` | Start configured attack flow. |
| `/quick-test/start/` | Start quick test flow. |
| `/attack/<id>/` | Attack detail. |
| `/attack/<id>/plan/` | Plan view. |
| `/attack/<id>/phase-reviews/` | Phase review view. |
| `/attack/<id>/command-logs/` | Command logs. |
| `/attack/<id>/replay/` | Replay view. |
| `/targets/` | Target management. |
| `/executors/` | Attacker executor management. |
| `/configuration/` | AI and runtime configuration. |
| `/api/executor/heartbeat/` | Executor heartbeat. |
| `/api/executor/tasks/` | Executor task polling. |
| `/api/executor/tasks/<task_id>/result/` | Executor result submission. |

### 6.2 Management Commands

```powershell
python manage.py seed_phases_and_commands
python manage.py seed_targets
python manage.py add_target
python manage.py run_simulation
python manage.py fix_commands
```

### 6.3 Executor API

| Endpoint | Purpose |
| --- | --- |
| `POST /api/executor/heartbeat/` | Register executor liveness with the controller. |
| `GET /api/executor/tasks/` | Poll for pending execution tasks. |
| `POST /api/executor/tasks/<task_id>/result/` | Submit task output, status, and errors. |
| `POST /api/executor/results/` | Legacy result submission endpoint. |

## 7. Testing

### 7.1 Full Suite

```powershell
pytest
```

### 7.2 Focused Suites

```powershell
pytest ai\tests
pytest dashboard\tests
pytest services\tests
pytest parser\tests
pytest state\tests
```

### 7.3 Manual Checks

These scripts exercise local workflows or external provider adapters and are
kept outside pytest collection.

```powershell
python scripts/checks/check_adapters.py
python scripts/checks/check_executor_selection.py
python scripts/checks/check_workflow.py
python scripts/checks/check_integration_loop.py
```

## 8. Development Notes

- Keep secrets in `.env`; do not commit real keys or runtime databases.
- `db.sqlite3`, `.env`, virtual environments, cache folders, logs, and runtime
  artifacts are ignored by `.gitignore`.
- Prefer extending existing modules before adding new top-level packages.
- Add or update tests when changing AI routing, command rendering, execution,
  parsing, dashboard flows, or state management.
- Keep manual diagnostics in `scripts/checks/`, maintenance helpers in
  `scripts/maintenance/`, and historical notes in `docs/`.

## 9. Ethical Use

XploitAI is for authorized labs only. Do not point it at public systems,
third-party networks, or real user data. Any use outside controlled training and
research environments is outside the intent of the project.
