---
name: continuous-improvement
description: Dopisuje zasady Workflow Orchestration, Task Management i Core Principles do CLAUDE.md bieżącego projektu. Triggeruj gdy użytkownik mówi "dodaj zasady do CLAUDE.md", "continuous improvement", "dopisz workflow rules", "upgrade CLAUDE.md", "setup CLAUDE.md".
---

# Continuous Improvement — CLAUDE.md Upgrade

Adds proven workflow rules to the current project's CLAUDE.md.

## Your Task

1. **Read the current project CLAUDE.md** (in the current working directory)
   - If it doesn't exist, create it from scratch with just the new sections
   - If it exists, merge intelligently — don't duplicate rules already present

2. **Add the following sections** (skip any that already exist in equivalent form):

---

### Section to add: Workflow Orchestration

```markdown
## Workflow Orchestration

### 1. Plan Mode Default
- Enter plan mode for ANY non-trivial task (3+ steps or architectural decisions)
- If something goes sideways, STOP and re-plan immediately — don't keep pushing
- Use plan mode for verification steps, not just building
- Write detailed specs upfront to reduce ambiguity

### 2. Subagent Strategy
- Use subagents liberally to keep main context window clean
- Offload research, exploration, and parallel analysis to subagents
- For complex problems, throw more compute at it via subagents
- One task per subagent for focused execution

### 3. Self-Improvement Loop
- After ANY correction from the user: update `tasks/lessons.md` with the pattern
- Write rules for yourself that prevent the same mistake
- Ruthlessly iterate on these lessons until mistake rate drops
- Review lessons at session start for relevant project

### 4. Verification Before Done
- Never mark a task complete without proving it works
- Diff behavior between main and your changes when relevant
- Ask yourself: "Would a staff engineer approve this?"
- Run tests, check logs, demonstrate correctness

### 5. Demand Elegance (Balanced)
- For non-trivial changes: pause and ask "is there a more elegant way?"
- If a fix feels hacky: "Knowing everything I know now, implement the elegant solution"
- Skip this for simple, obvious fixes — don't over-engineer
- Challenge your own work before presenting it

### 6. Autonomous Bug Fixing
- When given a bug report: just fix it. Don't ask for hand-holding
- Point at logs, errors, failing tests — then resolve them
- Zero context switching required from the user
- Go fix failing CI tests without being told how
```

---

### Section to add: Task Management

```markdown
## Task Management

1. **Plan First** — write plan to `tasks/todo.md` with checkable items
2. **Verify Plan** — check in before starting implementation
3. **Track Progress** — mark items complete as you go
4. **Explain Changes** — high-level summary at each step
5. **Document Results** — add review section to `tasks/todo.md`
6. **Capture Lessons** — update `tasks/lessons.md` after corrections
```

---

### Section to add: Core Principles

```markdown
## Core Principles

- **Simplicity First** — make every change as simple as possible, impact minimal code
- **No Laziness** — find root causes, no temporary fixes, senior developer standards
- **Minimal Impact** — changes should only touch what's necessary, avoid introducing bugs
```

---

## Merge Rules

- If CLAUDE.md already has a `## Workflow` or `## Core Principles` section → append missing points only, don't overwrite
- Preserve all existing content — only ADD, never remove
- Place new sections at the END of the file, before any trailing notes
- Keep the existing file's style (language, tone, formatting)

## After Writing

Create `tasks/` directory and stub files if they don't exist:
```
tasks/
  todo.md     — current task list (empty template)
  lessons.md  — captured lessons (empty template)
```

Confirm to user:
```
✅ CLAUDE.md updated — added:
- Workflow Orchestration (6 rules)
- Task Management (6 steps)
- Core Principles (3 rules)

tasks/todo.md ✅
tasks/lessons.md ✅
```
