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

## Step 2 — Spawn 10 agents in parallel

Each agent gets the FULL symptom context + their specific task. Agents CANNOT speculate — every claim must have evidence (grep output, Read output, curl response, log line).

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

### Instructions for EACH agent

```
SYMPTOM CONTEXT:
[paste symptom from Step 0]

YOUR TASK:
[specific agent task]

RULES:
1. ZERO SPECULATION. Every claim must have evidence: grep output, Read output, curl response, log line, SQL query result.
2. Read files from DISK (Read tool), not from memory.
3. If you cannot confirm a hypothesis — write "NOT VERIFIED" instead of guessing.
4. ACTIVELY search — don't wait for evidence to appear. Grep, Read, curl, SSH — use your tools.
5. Return a CONCRETE result: "Value X at line Y in file Z comes from [source] because [evidence]".
```

## Step 3 — Collect results

After all agents complete:

1. **Timeline**: Assemble chronological timeline from agent 3 (logs) + 7 (timing) results
2. **Data trace**: Assemble full value trace from agent 1 (forward) + 2 (backward) + 8 (data flow)
3. **Root cause candidates**: Collect hypotheses from agent 9 + evidence from all agents
4. **Cross-validation**: Do agents agree? If NOT — that's where the bug is

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

### Blind Spots
[What was NOT verified and why]
```

## Rules

1. **ZERO SPECULATION** — "probably", "maybe", "seems like" are NOT answers. Find evidence or write "I DON'T KNOW".
2. **LITERAL OUTPUT** — every claim must have a $ command and output. "Checked, OK" = you didn't check.
3. **10 AGENTS IN PARALLEL** — always. Not 3, not 5. Full 10 perspectives.
4. **ONE ROOT CAUSE** — not "A or B". Pick the most likely and PROVE it.
5. **CROSS-VALIDATION** — if 2 agents give contradictory results, that's the KEY to the solution.
6. **FRESHNESS** — read from disk, not from memory. Logs from the server, not from imagination.
7. **TIMELINE FIRST** — before searching for the cause, build the full timeline. The cause hides in chronology.
8. **EVIDENCE > AUTHORITY** — not "this code looks correct". Only "this code with value X at line Y gives Z because [test/trace]".
9. **DON'T FIX** — the goal is UNDERSTANDING, not a fix. The fix is a separate step after RCA approval.
10. **CONFIDENCE** — if confidence < 80%, say so directly. An honest "I don't know" is better than a confident but wrong verdict.
