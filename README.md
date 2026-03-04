# XploitAI
**AI-Orchestrated Penetration Testing Simulation & Cyber Range Framework**

---

## 📌 Overview

**XploitAI** is an AI-orchestrated, policy-governed cybersecurity framework designed to **simulate and demonstrate the penetration testing attack lifecycle** in a safe, ethical, and fully controlled manner.

The system separates **AI decision-making** from **attack execution**, ensuring that artificial intelligence never executes commands directly. Instead, XploitAI models how attackers think, plan, and progress through the cyber kill chain while enforcing strict safety and architectural boundaries.

XploitAI is built in **phases**, starting with a **simulation-only control plane** and later integrating a real cyber range consisting of attacker and victim virtual machines.

---

## 🎯 Core Philosophy

> **AI decides.
> Policies validate.
> Executors act.
> Visualization explains.**

At no point does AI gain unrestricted system access.

---

## 🚦 Project Phases

XploitAI is intentionally split into **three phases** to prevent architectural drift and security violations.

---

## 🧩 Phase 1 — Control Plane & Simulation (Codespaces-Ready)

### Goal

Build the **entire brain and control system** of XploitAI without executing real attacks.

### What Phase 1 Includes

* AI decision engine (reasoning only)
* Policy engine (kill-chain enforcement)
* Action registry (atomic attack grammar)
* Simulation executor (mock attack outcomes)
* Attack state machine
* Audit logging & explainability
* Dashboard & attack visualization

### What Phase 1 Explicitly Excludes

* Kali Linux
* Metasploit / Nmap
* SSH or Paramiko
* Virtual machines
* Real exploits or scanning

> Phase 1 proves architecture correctness and AI discipline.

---

## 🧩 Phase 2 — Cyber Range Integration (Execution Plane)

### Goal

Attach **real attacker and victim VMs** to an already stable system.

### Adds

* Kali Linux attacker VM
* Intentionally vulnerable victim VM (Windows/Linux)
* SSH-based executor
* Real tool execution (via predefined actions only)

### Constraints

* **NO architectural changes**
* Executor is the only module replaced
* Policies and action definitions remain unchanged

---

## 🧩 Phase 3 — Advanced Intelligence & Training Platform

### Goal

Turn XploitAI into a **teaching and evaluation platform**.

### Adds

* Attack graphs
* MITRE ATT&CK mapping
* Scenario variations
* Student scoring & assessment
* Replay & comparison modes

---

## 🧠 System Architecture (High Level)

```
Dashboard
   ↓
Orchestration Core
   ↓
AI Agent (Decision Only)
   ↓
Policy Engine
   ↓
Action Registry
   ↓
Executor (Simulation / SSH)
   ↓
Attack State
```

**Key rule:**
AI never bypasses the policy engine.

---

## 📂 Repository Structure

```
xploitai/
├── agent/           # AI decision logic (no execution)
├── policy/          # Validation & safety rules
├── actions/         # Atomic attack definitions
├── executor/        # Simulation / SSH executors
├── core/            # Domain models & state machine
├── parsers/         # Output → structured data
├── dashboard/       # UI & visualization
├── logs/            # Audit & execution logs
├── agent/           # AI agent control files
│   ├── rules.md
│   ├── project_scope.md
│   ├── architecture.md
│   ├── tech_stack.md
│   ├── coding_standards.md
│   ├── todo.md
│   └── prompt_template.md
└── README.md
```

---

## 🤖 AI Agent Development Model

XploitAI uses a **strict agent sandbox** to prevent hallucinations and unsafe behavior.

The AI agent:

* Reads architecture and rules before coding
* Works on **one TODO at a time**
* Modifies **one file per task**
* Never invents features or folders
* Never executes commands

This structure works with:

* Gemini Code Assist
* GitHub Copilot
* Cursor
* Codex-style agents

---

## 🔐 Safety & Ethics (Non-Negotiable)

XploitAI is designed to be **ethically defensible**.

### Safety Guarantees

* AI cannot execute shell commands
* All actions are whitelisted
* Policy validation before execution
* Isolated environments only
* Dummy artifacts for proof of compromise

### Ethical Scope

* No real-world targets
* No scanning external networks
* No real data
* Educational & research use only

---

## 🧪 Simulation Mode (Phase 1)

Simulation mode allows:

* Full attack lifecycle execution
* Deterministic or probabilistic outcomes
* Testing AI reasoning without risk
* Dashboard development without VMs

Simulation is **mandatory** before real execution is added.

---

## 🛠️ Technology Stack

### Phase 1

* **Backend:** Django (with user authentication/authorization, email verification, password reset)
* **Language:** Python 3.12
* **Database:** SQLite
* **Frontend:** Django Templates (HTML + minimal JS)
* **AI:** External LLM API (decision-making only)

* **Roles:** Users are assigned to groups; admin functions (configuration) restricted to `Admin` group or superuser.

### Phase 2 (Adds)

* Kali Linux
* Vulnerable Windows/Linux VM
* SSH (Paramiko)
* Penetration testing tools (restricted execution)

---

## 🚀 Development Environment

### Recommended

* GitHub Codespaces (Phase 1)
* Local machine with ≥16 GB RAM (Phase 2)

### Why Codespaces Works

* Phase 1 is logic-heavy, not network-heavy
* No VM dependency
* Clean, reproducible environment

---

## 📋 Build Order (DO NOT SKIP)

1. Domain models (`AttackState`, `Action`, `Result`)
2. Action registry (attack grammar)
3. Policy engine
4. Simulation executor
5. AI decision interface
6. Orchestration loop
7. Dashboard & visualization
8. Audit logging
9. Only then → real VM executor

---

## 📈 Expected Outcomes

* Clear visualization of cyber attack lifecycles
* Explainable AI decision-making
* Safe penetration testing demonstrations
* Reusable training and teaching platform

---

## 🧠 What XploitAI Is NOT

* ❌ A hacking tool
* ❌ A red-team automation framework
* ❌ An AI exploit generator
* ❌ A real-world attack system

It is a **controlled, educational orchestration framework**.

---

## 📌 Future Work

* Web application attack simulation
* Wireless attack modeling
* Attack graph generation
* MITRE ATT&CK correlation
* Student scoring & certification labs

---

## 📜 License & Disclaimer

This project is intended **strictly for educational and research purposes** within isolated environments.

Any misuse of this framework outside controlled labs is strictly prohibited and against the intent of the project.

---

## 🧭 Final Note

If you understand **why** XploitAI is structured this way,
you already understand **how real secure AI systems are built**.

---

