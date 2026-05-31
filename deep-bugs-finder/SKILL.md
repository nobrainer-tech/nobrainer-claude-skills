---
name: deep-bugs-finder
description: "Adversarially hunt for REAL bugs in code and write each verified bug to a bugs/ folder as its own markdown file with a proposed fix. Use when the user says 'deep bugs finder', 'find bugs', 'bug hunt', 'znajdz bugi', 'szukaj bugow', 'poluj na bugi', 'deep bug hunt', or wants a thorough adversarial defect sweep of a diff, branch, commit, or set of files. Loops until dry; verifies every finding against the real code before recording it."
---

# Deep Bugs Finder

Find real bugs and record each one in `bugs/` as a separate `.md` file with a
concrete proposed fix.

> Installed helper: `/Users/nobrainer-tech/.claude/skills/deep-bugs-finder/scripts/bug-hunt`
> Bug-file template: `/Users/nobrainer-tech/.claude/skills/deep-bugs-finder/assets/bug-template.md`
> Engine-agnostic: `--engine codex` (default) · `--engine claude` · `--engine both` (cross-model).

## The loop is script-driven (works for Codex AND Claude)

steipete saw Codex loop *internally* when told a bug exists. **We do not rely on
any model looping by itself.** The `bug-hunt` helper drives the loop in bash: it
re-invokes the chosen engine once per round, each round fed the assertion *"a bug
exists, find it"* plus the titles already found (*"don't repeat these — find
deeper ones"*). So the loop behaves identically whether the engine is Codex or
Claude — the universality comes from the harness, not the model. `--engine both`
runs Codex and Claude each round for cross-model coverage (they catch different
bug classes; that disagreement is signal).

## The method (why this works)

Source: [@steipete](https://x.com/steipete/status/2060672154727825718) —
*"Ask it to review code for bugs and it will tell you all good; tell it there IS a
bug and it will LOOP AND LOOP and will find issues."* (quoting the insight that
asserting a problem exists — "there is a simpler way", "there is a bug" — before
the model justifies itself produces far better results than a neutral ask.)

So this skill does NOT ask *"are there bugs?"* (the model answers *"looks good"*).
It **asserts a real bug exists** and **loops**, each round told what was already
found and pushed to dig for different, deeper defects — until it goes dry.

**But adversarial pressure invents false positives.** The discipline that makes
this useful instead of noisy: **every candidate is verified against the real code
before it becomes a bug file.** Pressure to find + rigor to confirm.

## Workflow

### 1. Pick scope
- Uncommitted work: `--diff`
- Branch/PR: `--base origin/main` (use the real PR base if `gh pr view` works)
- One commit: `--commit <ref>`
- Specific files: `--paths "core/x.py core/y.py"`
- No scope from the user → default to the working-tree diff; if clean, ask what to hunt (a path, a branch, or "whole module X").

### 2. Run the adversarial loop
```bash
/Users/nobrainer-tech/.claude/skills/deep-bugs-finder/scripts/bug-hunt --base origin/main --rounds 4
```
Candidates land in `bugs/.bug-hunt-candidates.md` (and stdout). Big scopes: codex
rounds can each take minutes — that is normal, let them finish. For a large module
you may also fan out: run several `bug-hunt` invocations over different file
subsets, or spawn parallel subagents each adversarially hunting one area.

You may run the loop yourself instead of the helper when you want full control —
the rule is the same: **assert a bug exists, demand file:line + a concrete failure
scenario + a fix, feed back what was found, repeat until two consecutive dry rounds.**

### 3. VERIFY every candidate (gate — do not skip)
For each candidate, before writing a bug file, confirm ALL three:
1. **Proven from code** — open the cited `file:line`, read it and its callers/callees. The failure must be reachable with real inputs, not hypothetical.
2. **Concrete failure mode** — you can state the exact input/state/sequence that produces wrong behaviour (crash, wrong result, data loss, security hole, hang, silent failure).
3. **Not intentional** — it isn't a deliberate codebase pattern, a guarded case, or already handled elsewhere. Check suppressions (`# noqa`, `# type: ignore`) by reading what they suppress before calling them wrong.

Reject: style/nits, speculative risks, "could be cleaner", broad rewrites,
unreachable edge cases, and anything you cannot trace to real code. A rejected
candidate is dropped (or recorded with `Status: rejected` only if it's instructive).

### 4. Write each REAL bug to its own file
- Folder: `bugs/` at the repo root (create if missing).
- One file per bug: `bugs/BUG-<NNN>-<kebab-slug>.md`, `<NNN>` zero-padded, incrementing (continue from the highest existing number — never overwrite).
- Use the template at `assets/bug-template.md`: title, severity, exact location, **why it's a real bug (proof, with the offending code)**, root cause, **proposed fix (diff/code)**, and a regression-guard test. Fill every section; no placeholders.
- Order by severity in the title number where practical (Critical first), but never renumber existing files.

### 5. Maintain `bugs/README.md` index
A table: `| ID | Severity | Title | Location | Status |`, one row per bug file,
newest first. Create it if absent; append/refresh rows for this run. Delete the
scratch `bugs/.bug-hunt-candidates.md` when done (it's working state, not output).

### 6. Report back
- Scope + rounds run + engine.
- Count of candidates raised vs **verified real bugs written** vs rejected (with one-line reasons for notable rejects).
- The list of new `bugs/BUG-*.md` files by severity.
- Do NOT auto-apply fixes unless the user asked — this skill records bugs+fixes; applying them is a separate, explicit step.

## Rules
- **Assert, then verify.** The adversarial framing finds more; the verification gate keeps it true. Never write a bug file you haven't traced in the real code.
- **One bug per file**, self-contained, with a proposed fix and a regression test idea.
- **Loop until dry** (≥2 empty rounds), not just one pass. The whole point is the loop.
- **No fixing unless asked.** Output = the `bugs/` folder. Fixing is opt-in.
- **Severity honestly.** Critical = data loss / security / money / corruption / crash on common path. Medium is the floor; don't pad with Lows.
- Keep findings at the right ownership boundary; propose the smallest fix that kills the bug class.
