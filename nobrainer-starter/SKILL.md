---
name: nobrainer-starter
description: Project starter - creates AGENTS.md and CLAUDE.md with NoBrainer engineering standards and workflow rules. Use when starting a new project or bootstrapping an existing one. Trigger on "setup project", "init project", "nobrainer-starter", "create AGENTS.md", "bootstrap project standards".
---

# NoBrainer Project Starter

Bootstraps a project with engineering standards (AGENTS.md) and workflow rules (CLAUDE.md).

## Your Task

1. **Check current working directory** for existing AGENTS.md and CLAUDE.md
2. **Create or merge AGENTS.md** with engineering principles (never overwrite existing content — merge)
3. **Create or merge CLAUDE.md** with workflow rules (never overwrite existing content — merge)
4. **Create tasks/ directory** with stub files if not present

---

## AGENTS.md — Full Content to Write

If AGENTS.md does not exist, create it. If it exists, merge intelligently — add only missing sections.

```markdown
# AGENTS.md — Engineering Standards

## Core Engineering Principles

- **DRY (Don't Repeat Yourself)** — eliminate code duplication.
- **KISS (Keep It Simple, Stupid)** — prefer simplicity and minimalism.
- **SOLID** — follow all five OOP principles for clean architecture.
- **YAGNI (You Ain't Gonna Need It)** — implement only what is required now.
- **Clean Code** — focus on readability, consistency, and maintainability.
- **Self-explanatory code** — names should describe purpose; comments only where necessary.
- **Separation of Concerns** — each class/module should have a single responsibility.
- **Encapsulation** — hide internal logic, expose only required interfaces.
- **Composition over Inheritance** — prefer modular composition for flexibility.
- **Fail Fast** — validate inputs early and handle errors explicitly.
- **Immutable Data** — avoid unintended state changes where possible.
- **Dependency Injection** — improve modularity and enable easy testing.
- **Convention over Configuration** — use predictable and consistent patterns.
- **Single Source of Truth** — avoid duplicating state or logic.
- **Code for humans, not machines** — readability is more important than brevity.
- **Testability** — design so code can be easily unit and integration tested.
- **Error Handling** — provide meaningful, user-safe error responses.
- **Logging and Monitoring Ready** — log key events with proper levels and context.
- **Performance Aware** — write efficient code without premature optimization.
- **Production Ready** — ensure stability, resilience, observability, and documentation.

## Structural and Design Recommendations

- Use POM (Page Object Model) or layered architecture to separate UI, logic, and data.
- Maintain clear naming conventions for variables, functions, and classes.
- Avoid magic numbers and hardcoded values — use constants or enums.
- Keep functions small and focused — each should perform one logical action.
- Don't comment bad code — rewrite it.
- Write once, read many — optimize for readability and long-term maintenance.
- Prefer explicitness over implicitness — avoid hidden behavior or side effects.
- Consistent formatting and indentation — follow language style guides.
- Meaningful structure — organize code into logical, reusable modules.

## Communication and Work Ethics

- **No Documentation Unless Explicitly Requested** — write self-documenting code. Only create docs, READMEs, or extensive comments when specifically asked.
- **Pareto Principle (80/20 Rule)** — focus on the 20% of features that deliver 80% of the value. Prioritize high-impact solutions.
- **Uncertainty Verification** — when uncertain about requirements or best practices, state it explicitly and ask before proceeding.
- **No Emoji Usage** — maintain professional communication without emojis in code, comments, or responses.
- **Single Method Approach** — use one proven method per problem. Avoid multiple fallback solutions unless explicitly asked for options.
- **Silent Best Practices** — apply engineering principles without announcing them in comments. Code demonstrates good practices through structure, not methodology commentary.

## General Expectations

- Output must be clean, consistent, and executable.
- Include minimal but clear comments where they add context.
- Avoid unnecessary libraries and dependencies.
- Always assume the code will go to production.
- Prioritize clarity, correctness, and maintainability over cleverness.
- Final output must be ready for real-world deployment with no major refactoring required.

## Implementation Guidelines

1. Start with the core functionality that delivers the most value.
2. Question assumptions and verify requirements when unclear.
3. Write code that explains itself through clear naming and structure.
4. Test critical paths but don't over-engineer test coverage initially.
5. Optimize for change by keeping components loosely coupled.
6. Document only when necessary — focus on why, not what.
7. Communicate uncertainties clearly and seek confirmation.
8. Deliver working solutions incrementally rather than waiting for perfection.
```

---

## CLAUDE.md — Full Content to Write

If CLAUDE.md does not exist, create it. If it exists, merge intelligently — add only missing sections.

```markdown
# CLAUDE.md

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

## Task Management

1. **Plan First** — write plan to `tasks/todo.md` with checkable items
2. **Verify Plan** — check in before starting implementation
3. **Track Progress** — mark items complete as you go
4. **Explain Changes** — high-level summary at each step
5. **Document Results** — add review section to `tasks/todo.md`
6. **Capture Lessons** — update `tasks/lessons.md` after corrections

## Core Principles

- **Simplicity First** — make every change as simple as possible, impact minimal code
- **No Laziness** — find root causes, no temporary fixes, senior developer standards
- **Minimal Impact** — changes should only touch what's necessary, avoid introducing bugs

## Git Rules

- Never commit without explicit user approval
- Never commit directly to main/master — always use branches and PRs
- Create PR only when explicitly asked
- No large volumes of redundant files — patch files in place, don't create versioned copies
```

---

## tasks/ Stub Files

Create `tasks/` directory and the following files if they don't exist:

**tasks/todo.md:**
```markdown
# TODO

## Current Task

- [ ] ...

## Completed

- [x] Project initialized with NoBrainer standards
```

**tasks/lessons.md:**
```markdown
# Lessons Learned

## Format

Each entry: date, what went wrong, rule to prevent recurrence.

---
```

---

## Merge Rules

- If a file already contains an equivalent section, skip it — don't duplicate
- Preserve all existing content — only ADD, never remove
- Place new sections at the END of existing files
- Keep existing file's style and language

## After Writing

Confirm to user:

```
Project bootstrapped:

AGENTS.md — engineering standards
CLAUDE.md — workflow rules + git rules
tasks/todo.md — task tracker
tasks/lessons.md — lessons log
```
