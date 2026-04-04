---
name: deep-audit
description: Universal evidence-based post-implementation verification. Backward line-by-line review, concrete value traces, caller audits with shown grep output. Works with any language/framework. Use after completing a feature/refactor/fix, BEFORE committing.
effort: max
argument-hint: "[quick | standard | deep]"
---

Evidence-based backward verification of completed work. Enforces line-by-line review, creative cross-checking methods, and active bug hunting. Universal — works with any language and framework.

Triggers: "audit", "verify", "check thoroughly", "backward tests", "find bugs", "line by line", "review changes", "post-implementation review"

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

## Step 1.5 — Orchestrator pre-processing (STANDARD + DEEP)

Before spawning subagents (if scope > 5 files), extract structured inputs:

### 1.5a — Extract S1 (structural) and S2 (semantic) inputs from diffs

```bash
cd "$PROJECT_ROOT"

# S1 — Structural: what changed physically
CHANGED_FILES=$({ git diff --name-only; git diff --cached --name-only; } | sort -u)
CHANGED_SIGNATURES=$(git diff -U0 | grep -E '^\+.*(function |def |func |fn |class |interface |type |export )' | head -30)
CHANGED_IMPORTS=$(git diff -U0 | grep -E '^\+.*(import |require\(|from )' | head -20)

# S2 — Semantic: what the changes mean
CHANGE_TYPE="unknown"
echo "$CHANGED_FILES" | grep -q "migration\|schema\|\.sql" && CHANGE_TYPE="database"
echo "$CHANGED_FILES" | grep -q "auth\|session\|token\|jwt" && CHANGE_TYPE="security"
echo "$CHANGED_FILES" | grep -q "config\|\.env\|settings" && CHANGE_TYPE="configuration"
echo "$CHANGED_FILES" | grep -q "api/\|route\|endpoint\|handler" && CHANGE_TYPE="api"
```

### 1.5b — Load context files

```bash
PLAN=$(find "$PROJECT_ROOT" -maxdepth 3 -name "*plan*" -o -name "*todo*" 2>/dev/null | head -3)
RULES=$(find "$PROJECT_ROOT" -maxdepth 2 -name "CLAUDE.md" -o -name "AGENTS.md" -o -name "*.md" -path "*/.claude/rules/*" 2>/dev/null)
```

Pass S1, S2, CHANGE_TYPE, PLAN, and RULES to every subagent.

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
- [function]([values]) -> [trace result] -> OK / BUG

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

## Parallelization strategy (STANDARD + DEEP)

When scope > 5 files, split work across subagents (Agent tool). Orchestrator combines results into one report.

### Grouping heuristic (4 steps)

Before spawning, group files into subagent clusters:

1. **Split detection**: If a file was split (1->N), ALL resulting files go to ONE subagent — caller audit needs full context of both sides.
2. **Producer-consumer**: If changes touch both a data producer (API route, DB query, service) and its consumer (component, handler, page), pair them in one subagent.
3. **Cross-import**: If file A imports from changed file B, they go together. Check: `grep -l "from.*[changed-file]" $CHANGED_FILES`.
4. **Directory grouping**: Remaining files grouped by directory/domain (max 4 files per subagent).

### Work division

1. After Step 1 + 1.5 — group files using heuristic above
2. Spawn subagents in parallel (max 10):
   - Each subagent gets structured prompt (template below)
   - Each executes: Name & Path Verification, Backward review, Caller audit, Value trace, Hidden bugs
   - Each returns structured output (format below)
3. Orchestrator:
   - Collects results from all subagents
   - Runs 5-step merge (below)
   - Runs Step 5 (machine verification) — centrally
   - Combines into one report (Step 6)

### Prompt template for subagents

```
<context>
PROJECT_ROOT: [path]
LANG: [detected language]
MODE: [STANDARD or DEEP]
CHANGE_TYPE: [from Step 1.5a]
S1_CHANGED_FILES: [file list from this subagent's cluster]
S1_CHANGED_SIGNATURES: [relevant signatures]
S1_CHANGED_IMPORTS: [relevant imports]
PLAN: [plan file content or "NONE"]
DOMAIN_RULES: [relevant CLAUDE.md rules or "NONE"]
</context>

<task>
Execute Steps 1c through 4 of the deep-audit skill on your assigned files:
1. Name & Path Verification — verify every new symbol exists under that exact name
2. Backward line-by-line review — read EVERY changed line from disk, reverse order
3. Caller audit — grep all callers for changed signatures, show literal output
4. Value trace — run concrete values through non-trivial functions
5. Hidden bug hunt — consistency, edge cases, integration, copy-paste, project rules
</task>

<rules>
1. Read files from DISK (Read tool), NEVER from memory.
2. Every claim needs evidence: $ command + literal output.
3. "Checked, OK" without grep output = NOT checked.
4. Pick verification methods appropriate for file types (caller audit for signatures, truth table for conditions, value trace for functions).
</rules>

<output_format>
Return a structured list of findings:

FINDING: [one-line description]
FILE: [path]
LINE: [number]
SEVERITY: CRITICAL / WARNING / INFO
EVIDENCE: [$ command + literal output]
CONFLICTS_WITH: [subagent number, or NONE]

If no issues found:
CLEAN: [list of files reviewed]
METHODS_USED: [which verification methods applied]
EVIDENCE: [$ commands run to confirm clean]
</output_format>
```

### 5-step merge algorithm

After all subagents complete:

#### Merge 1 — Deduplicate
Group findings pointing to the same file:line. Keep the finding with highest severity and most evidence.

#### Merge 2 — Detect conflicts
Scan all `CONFLICTS_WITH` fields. For each conflict:
- Compare evidence side by side
- If one subagent had more context (e.g. saw both sides of a split) -> that one wins
- If equal evidence -> escalate (Merge 5)

#### Merge 3 — Validate CLEAN results
For each subagent that returned CLEAN:
- Check METHODS_USED — did it actually run caller audit + value trace?
- Check EVIDENCE — are there actual grep commands with output?
- If CLEAN but no evidence -> re-run that subagent with explicit instructions

#### Merge 4 — Cross-subagent integration check
For findings that touch exports/imports across subagent boundaries:
- Verify the change is consistent on BOTH sides
- If subagent A found a renamed export but subagent B didn't check consumers -> run targeted grep

#### Merge 5 — Escalation protocol
When subagents contradict or evidence is ambiguous:
1. Re-run conflicting subagent with the other's findings as additional context
2. If still contradictory -> spawn a tiebreaker subagent with both outputs
3. If tiebreaker fails -> report both with confidence levels, let user decide

### Failure handling

**Bad output**: Subagent returns no findings and no CLEAN -> re-run with explicit file list and `--verbose`
**Suspicious CLEAN**: CLEAN with no EVIDENCE commands -> reject, re-run with mandatory grep/read output
**Timeout**: Subagent doesn't return in 5 min -> kill, log "TIMEOUT", continue with others, note in Blind Spots

### When NOT to parallelize

- scope <= 5 files — do sequentially, subagent overhead not worth it
- QUICK mode — too few steps, nothing to split

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
10. **Parallelize when scope > 5 files** — subagents per domain, orchestrator combines report.
11. **HANDLE FAILURES** — bad output, suspicious CLEAN, timeout are expected. Handle them, don't ignore them.
12. **STRUCTURED OUTPUT** — every subagent returns FINDING + EVIDENCE + SEVERITY + CONFLICTS_WITH. No free-form prose.
