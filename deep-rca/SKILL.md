---
name: deep-rca
description: Root Cause Analysis with 10 parallel agents. Reverse-engineers unexpected behavior by tracing code paths, checking logs, testing API calls, and cross-validating hypotheses. Zero speculation — every claim backed by grep output, code trace, or runtime evidence.
effort: max
argument-hint: "<description of unexpected behavior>"
---

Deep Root Cause Analysis — 10 agents, zero guessing, full verification.

Triggers: "rca", "root cause", "why is this happening", "where does this come from", "what caused this", "diagnosis", "reverse engineer", "trace bug", "what went wrong"

## When to use

When UNEXPECTED system behavior has been observed and you need to find the cause. Not for code auditing — for investigation. Difference: /deep-audit looks for potential bugs in code, /deep-rca explains a SPECIFIC incident that already happened.

## Step 0 — Define the symptom

Before doing anything — record EXACTLY what happened:

```
SYMPTOM: [what was observed — specific value, behavior, error]
EXPECTED: [what should have happened]
WHEN: [when it happened — timestamp, version, conditions]
CONTEXT: [additional context — environment, configuration, what happened before]
```

If the user didn't provide full context — ASK before starting. Don't guess.

## Step 1 — Auto-detect environment

```bash
PROJECT_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
LANG=$([ -f "requirements.txt" -o -f "pyproject.toml" ] && echo python || ([ -f "tsconfig.json" ] && echo typescript || ([ -f "go.mod" ] && echo go || ([ -f "Cargo.toml" ] && echo rust || ([ -f "pom.xml" -o -f "build.gradle" ] && echo java || echo unknown)))))
```

## Step 1.5 — Orchestrator pre-processing

Before spawning agents, the orchestrator extracts structured inputs from the symptom and environment:

### 1.5a — Collect diffs and recent changes

```bash
cd "$PROJECT_ROOT"

# Recent commits in symptom timeframe
git log --oneline --since="[WHEN from Step 0]" --until="now" 2>/dev/null | head -20

# Files changed recently
git diff --name-only HEAD~5..HEAD 2>/dev/null

# Unstaged changes
git diff --stat 2>/dev/null
```

### 1.5b — Extract S1 (structural) and S2 (semantic) inputs

From the diffs, extract two input sets for agents:

**S1 — Structural inputs** (what changed physically):
- List of changed files with domains (api/core/db/config/test)
- Changed function signatures (grep for `function|def|func|fn` in diffs)
- Changed imports/exports
- Changed config values

**S2 — Semantic inputs** (what the changes mean):
- Which subsystems are affected (auth, data pipeline, API, UI, cron)
- Whether changes cross subsystem boundaries
- Whether changes touch error handling or fallback paths

### 1.5c — Load context files

```bash
# Plan file (if exists)
PLAN=$(find "$PROJECT_ROOT" -maxdepth 3 -name "*plan*" -o -name "*todo*" 2>/dev/null | head -3)

# Domain rules
RULES=$(find "$PROJECT_ROOT" -maxdepth 2 -name "CLAUDE.md" -o -name "AGENTS.md" -o -name "*.md" -path "*/.claude/rules/*" 2>/dev/null)

# Change type classification
CHANGE_TYPE="unknown"
git diff --name-only HEAD~5..HEAD 2>/dev/null | grep -q "migration\|schema\|\.sql" && CHANGE_TYPE="database"
git diff --name-only HEAD~5..HEAD 2>/dev/null | grep -q "auth\|session\|token\|jwt" && CHANGE_TYPE="security"
git diff --name-only HEAD~5..HEAD 2>/dev/null | grep -q "config\|\.env\|settings" && CHANGE_TYPE="configuration"
git diff --name-only HEAD~5..HEAD 2>/dev/null | grep -q "api/\|route\|endpoint\|handler" && CHANGE_TYPE="api"
```

Pass PLAN, RULES, CHANGE_TYPE, S1, and S2 to every agent as additional context.

## Step 2 — Spawn 10 agents in parallel

Each agent gets the FULL symptom context + S1/S2 inputs + plan/rules/change-type + their specific task. Agents CANNOT speculate — every claim must have evidence (grep output, Read output, curl response, log line).

### Agent grouping heuristic

Before spawning, group the 10 agents into coordination clusters using this 4-step heuristic:

1. **Split detection**: If S1 shows a file was split (1->N), agents touching those files MUST share context. Put Agent 1 (forward trace) and Agent 2 (backward trace) in one cluster.
2. **Producer-consumer**: If S1 shows changes in both a data producer (API, DB query) and consumer (UI, handler), pair Agent 5 (dependency tester) with Agent 8 (data flow validator).
3. **Cross-import**: If S1 shows changed exports/imports across >3 files, Agent 4 (config inspector) and Agent 8 (data flow) share findings before final report.
4. **Directory grouping**: Remaining agents run independently, grouped by the directory of files they'll primarily investigate.

### Responsibility split

**Agent 1 — Code Path Tracer (Forward)**
Read the code from entry point to where the symptom manifests. Trace EVERY variable, EVERY condition, EVERY return. Show full trace with line numbers and values.

**Agent 2 — Code Path Tracer (Backward)**
Start from the symptom (value, behavior) and go BACKWARD — who set this value? Where did it come from? What transformations did it go through? Trace to source.

**Agent 3 — Log Analyst**
Search logs (application, server, service) in the incident time window. Look for: ERROR, WARNING, unexpected values, state changes. Build event timeline with timestamps.

**Agent 4 — Config & State Inspector**
Check ALL configuration at incident time: config files, env vars, database settings, defaults in code. Is any config value different than expected?

**Agent 5 — External Dependency Tester**
Test external dependencies (APIs, databases, services) with the same parameters as the system at incident time. Does the dependency return what we expect? Curl + parse + compare.

**Agent 6 — Cache & State Machine Analyst**
Check all caches, TTLs, stale data paths. Could the value have come from a stale cache? Check timestamps, invalidation logic, race conditions between cache write and read.

**Agent 7 — Timezone & Timing Analyst**
Check EVERY timestamp in the incident. Convert UTC to local and back. Check cron jobs, interval gates, TTL expirations, scheduling logic. Is anything time-sensitive behaving incorrectly?

**Agent 8 — Data Flow Validator**
Follow data from source (API/DB/input) through every transformation (parse, convert, round, cache) to destination (DB, output, response). At EACH step show the value. Where does the value change?

**Agent 9 — Hypothesis Killer**
Take the 3 most obvious hypotheses for what could have caused the symptom. For EACH — find EVIDENCE that confirms or disproves it. Not "maybe it's X" — only "X is/is not the cause because [evidence]".

**Agent 10 — Similar Incident Finder**
Search git log, logs, history — has the same symptom occurred before? When? Was it fixed? Could the fix have regressed?

### Prompt templates

Each agent gets a structured prompt. Use these templates exactly:

**S1-focused agents (1, 2, 8) — Code/Data tracers:**

```
<context>
SYMPTOM: [from Step 0]
PROJECT_ROOT: [path]
LANG: [detected language]
CHANGE_TYPE: [from Step 1.5c]
S1_CHANGED_FILES: [file list with domains]
S1_CHANGED_SIGNATURES: [function signatures from diffs]
PLAN: [plan file content or "NONE"]
DOMAIN_RULES: [relevant CLAUDE.md rules or "NONE"]
</context>

<task>
[Agent-specific task description from responsibility split above]
</task>

<rules>
1. ZERO SPECULATION. Every claim must have evidence: grep output, Read output, curl response, log line.
2. Read files from DISK (Read tool), not from memory.
3. If you cannot confirm — write "NOT VERIFIED: [what you tried]".
4. Return structured output:
   FINDING: [one-line summary]
   EVIDENCE: [$ command + literal output]
   CONFIDENCE: [HIGH/MEDIUM/LOW]
   CONFLICTS_WITH: [agent number, if any, or NONE]
</rules>

<output_format>
Return a list of findings. Each finding MUST have:
- FINDING: one-line description
- EVIDENCE: literal command + output (not "I checked")
- FILE:LINE: exact location
- CONFIDENCE: HIGH/MEDIUM/LOW
- CONFLICTS_WITH: NONE or agent number
</output_format>
```

**S2-focused agents (3, 4, 5, 6, 7) — Environment/state investigators:**

```
<context>
SYMPTOM: [from Step 0]
PROJECT_ROOT: [path]
WHEN: [timestamp from Step 0]
S2_SUBSYSTEMS: [affected subsystems]
S2_CROSS_BOUNDARY: [true/false — do changes cross subsystem boundaries]
S2_ERROR_PATHS: [true/false — do changes touch error handling]
CHANGE_TYPE: [from Step 1.5c]
DOMAIN_RULES: [relevant rules or "NONE"]
</context>

<task>
[Agent-specific task description]
</task>

<rules>
[Same rules block as S1 template]
</rules>

<output_format>
[Same output_format block as S1 template]
</output_format>
```

**Synthesis agents (9, 10) — Hypothesis testing:**

```
<context>
SYMPTOM: [from Step 0]
PROJECT_ROOT: [path]
S1_CHANGED_FILES: [file list]
S2_SUBSYSTEMS: [affected subsystems]
CHANGE_TYPE: [from Step 1.5c]
</context>

<task>
[Agent-specific task description]
</task>

<rules>
[Same rules block]
For Agent 9 specifically: test EXACTLY 3 hypotheses. For each:
- STATE the hypothesis in one sentence
- List 2-3 pieces of evidence that would CONFIRM it
- List 2-3 pieces of evidence that would DISPROVE it
- SEARCH for each piece of evidence (grep, Read, curl)
- VERDICT: CONFIRMED / DISPROVED / INCONCLUSIVE + evidence
</rules>

<output_format>
HYPOTHESIS_1: [statement]
  CONFIRM_EVIDENCE: [what you found]
  DISPROVE_EVIDENCE: [what you found]
  VERDICT: CONFIRMED/DISPROVED/INCONCLUSIVE
  EVIDENCE: [$ command + output]

[repeat for hypotheses 2 and 3]
</output_format>
```

## Step 3 — Merge results (5-step algorithm)

After all agents complete, merge their findings using this algorithm:

### 3.1 — Deduplicate

Group findings that point to the same file:line or same root cause. Keep the finding with the highest confidence and most evidence.

### 3.2 — Detect conflicts

Scan all `CONFLICTS_WITH` fields. For each conflict:
- Read both agents' evidence side by side
- If evidence is from different timeframes → the newer one wins
- If evidence is from the same timeframe → escalate (Step 3.5)

### 3.3 — Build timeline

Merge Agent 3 (logs) + Agent 7 (timing) timelines into one chronological view. Insert findings from other agents at their relevant timestamps.

### 3.4 — Assemble evidence chain

Take Agent 1 (forward trace) + Agent 2 (backward trace) + Agent 8 (data flow). These three MUST form a continuous chain from source to symptom. If there's a gap:
- Identify the gap boundaries (last known value → first value after gap)
- Check if Agent 6 (cache) or Agent 4 (config) fills the gap
- If still a gap → report it as a blind spot

### 3.5 — Escalation protocol

When agents contradict each other and evidence is equally strong:

1. **Re-run the conflicting agents** with each other's findings as additional context
2. If still contradictory → spawn an **Agent 11 (Tiebreaker)** that:
   - Gets both agents' full output
   - Must find ONE piece of evidence that resolves the conflict
   - Has access to runtime testing (can run code, curl APIs, query DB)
3. If tiebreaker also fails → report BOTH hypotheses with confidence levels and let the user decide

## Step 3.5 — Failure handling

### Bad output from an agent

If an agent returns:
- No findings at all → re-run with `--verbose` flag and explicit file list
- Only "NOT VERIFIED" for everything → check if the agent had access to the right files/logs. Re-run with corrected paths.
- Malformed output (no EVIDENCE fields) → parse what you can, log "PARTIAL OUTPUT" for that agent

### Suspicious CLEAN result

If Agent 9 (Hypothesis Killer) disproves ALL 3 hypotheses → this is suspicious. Before accepting:
1. Check if the hypotheses were too narrow (all variations of the same idea)
2. Generate 3 NEW hypotheses from a different angle (timing, config, external dependency)
3. Re-run Agent 9 with the new hypotheses

### Timeout

If an agent doesn't return within 5 minutes:
1. Kill it
2. Log "TIMEOUT: Agent [N] — [task description]"
3. Continue with remaining agents' results
4. Note the missing perspective in Blind Spots

## Step 4 — Verdict

Present ONE root cause (not "maybe A or B"):

```
## Root Cause Analysis — [date]

### Symptom
[what was observed]

### Root Cause
[ONE cause with evidence]

### Evidence Chain
1. [fact 1 + evidence]
2. [fact 2 + evidence]
3. [fact 3 + evidence]
-> CONCLUSION: [cause]

### Timeline
| Time | Event | Source |
|------|-------|--------|

### Data Trace
[value] -> [transformation 1] -> [value] -> ... -> [symptom]

### Contributing Factors
- [factor 1 — why it made the bug easier to occur]
- [factor 2]

### Was This Preventable?
[Was there a guard/check that should have caught this? Why didn't it?]

### Recommended Fix
[Specific code/config change — not generalities]

### Similar Past Incidents
[Has this happened before? When?]

### Confidence Level
[HIGH/MEDIUM/LOW] — [why this confidence level]

### Agent Agreement
[N]/10 agents support this conclusion
Conflicts resolved: [list or NONE]
Escalations triggered: [list or NONE]

### Blind Spots
[What was NOT verified and why]
[Timed-out agents: list or NONE]
[Gaps in evidence chain: list or NONE]
```

## Rules

1. **ZERO SPECULATION** — "probably", "maybe", "seems like" are NOT answers. Find evidence or write "I DON'T KNOW".
2. **LITERAL OUTPUT** — every claim must have a $ command and output. "Checked, OK" = you didn't check.
3. **10 AGENTS IN PARALLEL** — always. Not 3, not 5. Full 10 perspectives.
4. **ONE ROOT CAUSE** — not "A or B". Pick the most likely and PROVE it.
5. **CROSS-VALIDATION** — if 2 agents give contradictory results, that's the KEY to the solution. Use the escalation protocol.
6. **FRESHNESS** — read from disk, not from memory. Logs from the server, not from imagination.
7. **TIMELINE FIRST** — before searching for the cause, build the full timeline. The cause hides in chronology.
8. **EVIDENCE > AUTHORITY** — not "this code looks correct". Only "this code with value X at line Y gives Z because [test/trace]".
9. **DON'T FIX** — the goal is UNDERSTANDING, not a fix. The fix is a separate step after RCA approval.
10. **CONFIDENCE** — if confidence < 80%, say so directly. An honest "I don't know" is better than a confident but wrong verdict.
11. **HANDLE FAILURES** — bad output, suspicious CLEAN results, and timeouts are expected. Handle them, don't ignore them.
12. **STRUCTURED OUTPUT** — every agent returns FINDING + EVIDENCE + CONFIDENCE + CONFLICTS_WITH. No free-form prose.
