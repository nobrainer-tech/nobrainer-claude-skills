---
name: deep-audit
description: Universal evidence-based post-implementation verification. Backward line-by-line review, concrete value traces, caller audits with shown grep output. Works with any language/framework. Use after completing a feature/refactor/fix, BEFORE committing.
---

Evidence-based backward verification of completed work. Enforces line-by-line review, creative cross-checking methods, and active bug hunting. Universal — works with any language and framework.

Triggers: "deep audit", "post-implementation audit", "verify thoroughly", "backward tests", "line by line", "review completed changes"

Optional mode argument: `quick`, `standard`, or `deep`. Default to the risk-based
selection below when no mode is supplied.

## When to use

After completing implementation (feature, refactor, fix, split) — BEFORE committing. This skill enforces verification that no compiler/linter can replace.

## Step 0 — Detect & Triage

### Auto-detect project

```bash
PROJECT_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$PROJECT_ROOT"

# Detect language/framework
[ -f "tsconfig.json" ] && LANG="typescript"
[ -f "package.json" ] && FRAMEWORK="node"
[ -f "pom.xml" ] && LANG="java" && FRAMEWORK="maven"
[ -f "build.gradle" ] && LANG="java" && FRAMEWORK="gradle"
[ -f "requirements.txt" -o -f "pyproject.toml" -o -f "setup.py" ] && LANG="python"
[ -f "go.mod" ] && LANG="go"
[ -f "Cargo.toml" ] && LANG="rust"
[ -f "Gemfile" ] && LANG="ruby"
[ -f "composer.json" ] && LANG="php"
[ -f "*.sln" -o -f "*.csproj" ] && LANG="csharp"
```

Note: PROJECT_ROOT, LANG, FRAMEWORK — use them in subsequent steps.

### Choose mode

Assess change risk:

| Signal | Mode |
|---|---|
| CSS/style only, docs, config, dotfiles | QUICK — steps 1, 5, 6 |
| UI components, helpers, utilities (no core logic) | STANDARD — steps 1-6 |
| Core business logic, API contracts, auth, payment, database migrations, security, split 1->N | DEEP — steps 1-6 + step 3b |

If $ARGUMENTS = "quick" or "deep" -> force that mode.

### Cross-reference with plan

Check if a plan file exists:

```bash
PLAN=$(find . .claude ~/.claude -maxdepth 3 -name "*plan*" -newer "$(git log -1 --format=%aI)" 2>/dev/null | head -1)
[ -n "$PLAN" ] && echo "PLAN: $PLAN" || echo "NO PLAN"
```

If plan exists — read it and extract:
- "Done when" criteria per step — you will verify them in Step 2
- "Critical traps" list — you will check them in Step 4
- Integration test matrix — you will run it in Step 5
- Evidence log — compare with actual code state

Plan is a checklist. Analysis is an audit of that checklist.

## Step 1 — Collect scope

Identify ALL files changed/created in this session:

```bash
cd "$PROJECT_ROOT" && { git diff --name-only; git diff --cached --name-only; git ls-files --others --exclude-standard; } | sort -u
```

If no changes -> "No changes to analyze." and stop.

For each file note:
- Path and domain (ui / api / core / db / config / test / infra)
- Whether it's a NEW file or MODIFICATION of existing
- Lines changed (`git diff --stat`)

## Step 1b — Predict the bug (STANDARD + DEEP)

BEFORE reading the code — based on scope and change type alone, write 2-3 predictions of where you expect a bug. Examples:

- "Change in hook + new component -> likely new signature doesn't match some consumer"
- "File split -> likely lost export or changed return type"
- "Guard condition change -> likely inverted logic or missing edge case"
- "Math/calculations -> likely division by zero or Infinity"
- "SQL migration -> likely missing rollback or inconsistent with ORM models"
- "API endpoint change -> likely frontend not updated"

Record predictions. After review — check if you were right. If you missed ALL — keep looking, the bug is somewhere you didn't expect.

## Step 1c — Name & Path Verification (STANDARD + DEEP)

BEFORE starting code review — verify that every new symbol in changed files actually exists under that name.

For each changed file:
1. List NEW imports, function calls, references to external symbols
2. For EACH — grep confirms symbol exists under that exact name in target file

Show literal output:

```
- import { handleSeasonEnd } from './GameScene':
  $ grep -n "handleSeasonEnd" GameScene.ts
  (no results)
  $ grep -n "handleSeason" GameScene.ts
  1823:  handleSeasonEnded() {
  -> BUG: typo in import. Correct name: handleSeasonEnded

- store.setEndReached(true):
  $ grep -n "setEndReached" store.ts
  52:  setEndReached: (flag: boolean) => set({ endReached: flag }),
  -> OK
```

This catches: typos, "similar but wrong" names, stale paths after refactor, non-existent exports.

## Step 2 — Backward line-by-line review (STANDARD + DEEP)

FRESHNESS RULE: Read files from disk (Read tool), NEVER from context memory. Your memory of what you wrote carries the same bias that could have caused a bug. The file on disk is truth — your memory is not.

For EACH changed file (from last to first — reverse order):

1. Read the ENTIRE file from disk (Read tool — not a fragment, not from memory)
2. Read the diff: `git diff [file]` (for NEW files: diff doesn't exist — read entire file as "changed", with special attention to imports, exports, and types)
3. For EACH changed line ask yourself:
   - Does this line do exactly what it should?
   - Is there a typo in variable/function/property name?
   - Are types correct (no any, no missing await, not string instead of number)?
   - Is the logical condition inverted (e.g. extra/missing !, && vs ||)?
   - Is the import/require path correct and does the target file exist?
   - Is this dead code (unreachable, unused)?
4. If there was a plan with "Done when" criteria — verify each criterion for this step. Not "does it compile" but "did we do what the plan said".

IMPORTANT: Don't scan — READ. Every line. Record found issues as you go.

## Step 3 — Creative cross-verification (STANDARD + DEEP)

### 3a — Mandatory caller audit

For EACH changed function signature or export:

```bash
grep -rn "functionName" "$PROJECT_ROOT/src/" "$PROJECT_ROOT/lib/" "$PROJECT_ROOT/app/" 2>/dev/null
```

Show literal grep output in the report. For each caller — confirm signature matches. Not "5 callers, OK" but:

```
Caller audit: setCurrentState()
$ grep -rn "setCurrentState" src/
service.ts:234: setCurrentState(state)
poller.ts:67: setCurrentState(data)
handler.ts:12: setCurrentState(newState)
[...]
-> 9 callers, signatures match (State type)
```

If callers > 15 — show first 5 + "and [N] more, spot-check 3 random: [results]".

### 3b — Verification methods per change type (DEEP)

For each file choose an ADDITIONAL verification method:

| Change type | Verification method |
|---|---|
| New file extracted from existing | Compare with original: `git show HEAD:[original]` -> diff function by function. Anything lost? Return types identical? |
| Change in hook/store/state | Grep all consumers + show output |
| New function | Concrete value trace (see below) |
| Guard condition change | Truth table: list input combinations and paths |
| SQL/migration change | Check rollback, indexes, foreign keys, NULL handling |
| API endpoint change | Check if client/frontend uses new signature |
| CSS/style change | Check if classes exist, no conflicts, responsive works |
| Import changes | `grep -rn "from.*[filename]"` — does anyone import old path? |
| File split 1->N | List ALL exports from original -> confirm each export has new home |
| Security/auth change | Check access control, token validation, input sanitization |
| Config/env change | Check if new vars are in .env.example, CI/CD, docs |

### 3c — Concrete value trace

Pick functions and run CONCRETE values through them:
- DEEP: every non-trivial function in scope
- STANDARD: minimum 2 (riskiest + 1 random)

```
Trace: formatAmount(0.00000001)
-> value = 0.00000001, threshold check: < 0.01 -> true
-> return "< 0.01" OK

Trace: formatAmount(Infinity)
-> value = Infinity, threshold check: Infinity < 0.01 -> false
-> toFixed(2) -> "Infinity" — BUG: missing guard on !isFinite()
```

Show trace in report — don't skip it even if no bug found.

### 3d — "Explain to a junior" (STANDARD + DEEP)

For each non-trivial function in changed files:

1. Read ONLY the signature (name + params + return type) — write one sentence about what this function SHOULD do
2. Read the body — write one sentence about what this function ACTUALLY does
3. Compare both sentences — discrepancy = bug or unclear intent

This catches bugs where code "looks right" but does something different than intended.

## Step 4 — Hidden bug hunting (STANDARD + DEEP)

Actively search for these problem categories (check each):

### A. Consistency errors

- Variable/function names — consistent across entire scope? (e.g. isActive vs active vs isEnabled)
- Formatting — does new code use same patterns as rest of file?

### B. Edge cases

- What happens with null/undefined/0/''/[] as input?
- What happens with Infinity/NaN (JS/TS) or None/float('inf') (Python)?
- What happens when array/list is empty?
- What happens with concurrent calls (race condition)?
- What happens with very large input (memory, timeout)?

### C. Integration errors

- Is changed interface/type used elsewhere? (Grep on type name — show output)
- Is removed export imported in another file? (grep — show output)
- Does changed function signature match all call sites? (from Step 3a — confirm)

### D. Copy-paste errors

- Did I copy a variable from another block and forget to rename it?
- Do conditions in if/else if/else check the same thing?

### E. Project rules

Check if project rules exist:

```bash
find "$PROJECT_ROOT" -maxdepth 2 -name "CLAUDE.md" -o -name "AGENTS.md" -o -name "*.md" -path "*/.claude/rules/*" 2>/dev/null
```

Read the relevant rules file for the domain of changed files. For EACH applicable rule — CITE in report with literal grep output:

```
CLAUDE.md: "Never use any type"
  $ grep -n ": any" [changed-files]
  (no results)
  -> OK

CLAUDE.md: "Always validate input at API boundary"
  $ grep -n "req.body\|req.params\|req.query" [changed-files]
  handler.ts:42: const id = req.params.id
  -> VIOLATION: no validation
```

### F. Plan traps verification (if there was a /plan)

If plan had a "Critical traps" section — verify EACH with literal grep output.

## Step 5 — Machine verification

Run appropriate tools based on detected LANG:

```bash
cd "$PROJECT_ROOT"

# TypeScript/JavaScript
if [ -f "tsconfig.json" ]; then
  npx tsc --noEmit 2>&1 | tail -20
fi
if [ -f "package.json" ]; then
  CHANGED=$({ git diff --name-only; git diff --cached --name-only; } | sort -u | grep -E '\.(ts|tsx|js|jsx)$' | tr '\n' ' ')
  [ -n "$CHANGED" ] && npx eslint $CHANGED 2>&1 | tail -20
fi

# Python
if [ -n "$(find . -name '*.py' -newer .git/HEAD 2>/dev/null | head -1)" ]; then
  CHANGED_PY=$({ git diff --name-only; git diff --cached --name-only; } | sort -u | grep '\.py$' | tr '\n' ' ')
  [ -n "$CHANGED_PY" ] && python3 -m py_compile $CHANGED_PY 2>&1
  command -v ruff >/dev/null && [ -n "$CHANGED_PY" ] && ruff check $CHANGED_PY 2>&1 | tail -20
  command -v mypy >/dev/null && [ -n "$CHANGED_PY" ] && mypy $CHANGED_PY 2>&1 | tail -20
fi

# Java
if [ -f "pom.xml" ]; then
  mvn compile -q 2>&1 | tail -20
elif [ -f "build.gradle" ]; then
  ./gradlew compileJava -q 2>&1 | tail -20
fi

# Go
if [ -f "go.mod" ]; then
  go vet ./... 2>&1 | tail -20
fi

# Rust
if [ -f "Cargo.toml" ]; then
  cargo check 2>&1 | tail -20
fi

# Universal checks on new files
NEW_FILES=$(git ls-files --others --exclude-standard | grep -vE '\.(png|jpg|gif|svg|ico|woff|ttf|eot)$')
[ -n "$NEW_FILES" ] && file $NEW_FILES | grep -i crlf || echo "OK: no CRLF"
```

If a tool is not installed — skip and note in report.

## Step 6 — Report

META-CHECK before writing the report: Review every claim you intend to write. Do you have evidence from a tool (grep output, Read output, compiler output)? If not — don't write "OK", go back and check, or write "NOT VERIFIED".

Present results in format:

```
## Post-Implementation Audit — [date]

### Mode: QUICK / STANDARD / DEEP
### Environment: [LANG] / [FRAMEWORK] / [PROJECT_ROOT]

### Scope
- [N] files changed, [M] new
- Domains: [list]

### Predictions vs reality (STANDARD/DEEP)
- Prediction 1: [description] -> HIT / MISS
- Prediction 2: [description] -> HIT / MISS

### Name & Path Verification (STANDARD/DEEP)
- [symbol]: $ grep ... -> [output] -> OK / BUG

### Caller audit (STANDARD/DEEP)
- [function/export]: $ grep ... -> [N] callers, [summary]

### Concrete value traces (STANDARD/DEEP)
- `[function] with [values] -> [trace result] -> OK / BUG`

### Issues found

| # | File | Line | Problem | Severity | Evidence |
|---|------|------|---------|----------|----------|
| 1 | ... | ... | ... | CRITICAL / WARNING / INFO | [$ command + output] |

### Machine verification
- compiler: PASS / FAIL (N errors)
- linter: PASS / FAIL (N warnings)
- type checker: PASS / FAIL / SKIPPED
- line endings: PASS / FAIL

### Project rules (STANDARD/DEEP)
- [file] [section]: "[rule]" -> [$ command + output] -> OK / VIOLATION

### Plan verification (if there was a /plan)
- Done when criteria: [N]/[M] met
- Critical traps: [N]/[M] verified

### Blind spots — what was NOT verified
- [explicit list]

### Summary
[1-2 sentences: overall quality assessment + whether ready to commit]
```

If 0 issues -> "Clean audit. Ready to commit."
If CRITICAL -> fix BEFORE committing.
If WARNING -> propose fix, wait for decision.

## Execution model

**Default: sequential (single context).** The audit runs all steps sequentially in one context window. This produces more coherent results because each step builds on full awareness of previous findings. Cross-file patterns, subtle naming inconsistencies, and integration issues are easier to catch when one reviewer sees everything.

**Optional: parallel (--parallel flag).** Only use when scope > 15 files AND the user explicitly requests it. Parallelization trades coherence for speed — use it for massive refactors where sequential review would take too long, not as the default.

When running sequentially, process files in reverse order (last changed first) and carry forward a running list of findings. Each file review benefits from context accumulated from previous files.

## Rules

1. **DON'T TRUST YOURSELF** — assume you made a mistake. Actively search for it.
2. **DON'T RUSH** — thoroughness > speed.
3. **Compiler + linter is MINIMUM, not MAXIMUM** — Steps 2-4 catch what compilers can't see.
4. **Concrete values > abstract reasoning** — "this should work" is NOT verification. Trace with values.
5. **Reverse order** — reading from end breaks pattern recognition.
6. **Read like SOMEONE ELSE'S code** — not your own. You read your own with intent, someone else's with suspicion.
7. **Honest blind spots > false "all OK"** — the "what was NOT verified" section is honesty.
8. **Literal output > verbal claim** — "checked, OK" WITHOUT $ command and output = you did NOT check.
9. **Freshness** — read files from disk, not from context memory.
10. **Sequential by default** — single context gives better coherence. Only parallelize on explicit `--parallel` flag with scope > 15 files.
