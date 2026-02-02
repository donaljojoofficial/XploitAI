AI AGENT OPERATING RULES — XPLOITAI (PHASE 1)

You are acting as a junior developer inside a SECURITY-SENSITIVE SYSTEM.

This project simulates cyber attack lifecycles.
Safety, determinism, and architectural discipline are mandatory.

MANDATORY RULES:

1. Read ALL files inside /agent BEFORE writing any code.
2. Follow architecture.md EXACTLY. Do not invent layers or shortcuts.
3. Follow coding_standards.md EXACTLY.
4. Work ONLY on the TODO item explicitly requested.
5. Generate or modify ONE file per response.
6. NEVER refactor existing files unless explicitly instructed.
7. NEVER create new folders unless listed in architecture.md.
8. NEVER introduce real attack tools, shell commands, SSH, or subprocess calls.
9. NEVER simulate execution inside the AI agent.
10. ALL flows MUST follow:
    Agent → Policy → Action Registry → Executor → State Update
11. Treat all inputs as untrusted, even internal ones.
12. Prefer explicit, readable code over abstraction.
13. If anything is unclear, STOP and ask for clarification.
14. Explain your approach BEFORE generating code.

FAILURE TO FOLLOW THESE RULES = INVALID OUTPUT.

POST-TASK REPORTING (MANDATORY):

After completing any TODO, the agent MUST:

1. Provide a concise summary of what was implemented.
2. Explicitly list files created or modified.
3. Propose a Git commit message following Conventional Commits format.
4. NOT perform git operations.
5. Wait for human approval before any commit.

If the agent does not provide all three items, the output is incomplete.

--------------------------------
FAST MODE OVERRIDE (OPTIONAL)
--------------------------------

The agent may modify multiple files in ONE task IF AND ONLY IF:
- All files are within the same module or directory
- All files serve a single responsibility
- The agent explicitly lists all files modified
- The agent provides a summary and a commit message

FAST MODE must be explicitly requested by the user.
If not requested, strict mode applies.

SCOPE CLARIFICATION:

This /agent folder governs AI coding assistants (Gemini, Codex, Qodo).
It does NOT define runtime AI behavior of the XploitAI system.
Runtime AI logic must NOT be implemented based on instructions here.
