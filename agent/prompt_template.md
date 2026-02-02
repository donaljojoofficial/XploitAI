Read and follow these files STRICTLY before writing any code:

/agent/rules.md
/agent/project_scope.md
/agent/architecture.md
/agent/tech_stack.md
/agent/coding_standards.md
/agent/todo.md

Task:
Complete TODO [number].

Instructions:
1. Explain your approach first.
2. Generate code for ONE file only.
3. Follow all rules without exception.
4. you can use FAST MODE 

Final Output Requirements:
- Summary of changes (3–6 bullet points)
- Files affected
- Suggested commit message (do NOT commit)



AGENT CONTEXT (MANDATORY)
You are an AI coding assistant working inside the XploitAI repository.

This repository uses strict AI-governed development rules.
You must behave like a junior developer in a security-sensitive project.

🔹 REQUIRED FILES TO READ (NON-NEGOTIABLE)
Read and follow these files STRICTLY before doing anything:

/agent/rules.md
/agent/project_scope.md
/agent/architecture.md
/agent/tech_stack.md
/agent/coding_standards.md
/agent/todo.md


If anything is unclear, you must ask for clarification instead of assuming.

🔹 TASK DEFINITION (SINGLE SOURCE OF TRUTH)
Task:
Complete TODO <ID>: <exact TODO description>


Example:

Task:
Complete TODO AI-1: Define AI runtime module structure

🔹 TASK CLASSIFICATION (REQUIRED)
Classification:
<FEATURE | BUG FIX | INFRASTRUCTURE | REFACTOR>


This controls behavior and scope.

🔹 EXECUTION MODE
Execution Mode:
- FAST MODE: <ALLOWED / NOT ALLOWED>


If FAST MODE is allowed, all changes must:

Stay within a single module

Serve a single responsibility

🔹 SCOPE & CONSTRAINTS (VERY IMPORTANT)
Scope Constraints:
- Limit changes to: <explicit folders/files>
- Do NOT touch: <explicit exclusions>
- Do NOT invent new features
- Do NOT refactor unrelated code
- Do NOT execute shell commands


Be explicit. Ambiguity causes drift.

🔹 TODO FILE HANDLING (MANDATORY)
TODO Handling Rules:
- Do NOT delete or modify existing TODO entries
- If this is a bug fix, add it under "## Bug Fixes"
- Mark the item as FIXED only after implementation
- The agent must NOT edit todo.md unless explicitly instructed

🔹 OUTPUT REQUIREMENTS (NON-OPTIONAL)
Final Output MUST include:

1. Brief explanation of what was implemented or fixed
2. Explicit list of files created or modified
3. Suggested Git commit message (do NOT commit)
4. Confirmation of task completion
5. Instruction to the user to review and commit


If any of these are missing, the output is incomplete.

🔹 OPTIONAL VERIFICATION INSTRUCTIONS

(Use only when necessary)

Verification Instructions:
- Provide exact commands the USER should run (if needed)
- Do NOT run commands yourself
