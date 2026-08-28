---
name: nobrainer-ultra
description: "Use when the owner says nb-ultra, nb-flow, nb-workflow, ultracode, or asks to set up, upgrade, or reconcile a project's agent workflow; or wants one non-trivial task taken from brief requirements through a complete skill-routed plan, guarded autonomous execution, useful multi-session work and final evidence audit."
---

# NoBrainer Ultra

Turn one owner request into the best verified outcome the available project and
runtime can deliver. The owner states intent; Ultra hides routing complexity,
builds the complete execution map, invokes the right specialist methods and
keeps only real decisions behind human gates.

Read [references/routing.md](references/routing.md) before selecting methods. For
setup, upgrade, installation or workflow repair, also read
[references/setup.md](references/setup.md).
When the owner changes a decision, corrects the agent, or a review fails, read
[references/correction-hooks.md](references/correction-hooks.md) and execute the
matching correction hook before continuing.

## Lifecycle

Run this state machine on every non-trivial invocation:

`DRIFT_CHECK -> BUDDY -> EXECUTION_MAP -> READY_GATE -> AUTOPILOT -> VERIFY -> RECEIVE_AUDIT -> LEARN`

### 1. `DRIFT_CHECK`

Read the actual repository root, nearest instructions, dirty state,
branch/worktree, current goal/spec/plan, tests, verifiers, runtime, durable
knowledge, session registry and loaded capabilities. Compare them with the
requested outcome. Classify drift as `CLEAN`, `RECONCILABLE`, `OWNER_DECISION`
or `BLOCKED`. Preserve unrelated work and never trust stale titles or memory as
runtime state.

If a wiki exists, invoke `nobrainer-wiki` mode `GET` for only the decisions,
known constraints and confirmed preferences relevant to this task. If a material
external fact is current, niche, uncertain, high-stakes or source-attributed,
invoke `nobrainer-research` with the smallest sufficient rigor. Do not load a
whole vault or browse merely to look thorough.

`PROBLEM_GATE`: whenever execution encounters a problem, complication,
ambiguity, difficulty or error, pause before selecting a remedy. Invoke
`nobrainer-wiki` mode `GET` for only related decisions and lessons, then invoke
`nobrainer-research` for a current internet check. Reconcile both with the actual
repository/runtime; wiki is context, not current-state proof. If no wiki exists,
record that and continue to research. If internet research is required but
unavailable, stop at `RESEARCH_BLOCKED` instead of choosing from stale memory.

### 2. `BUDDY`

BUDDY is the first and only ordinary clarification stage. Establish:

- observable outcome, audience and quality bar;
- acceptance evidence and target workflow;
- scope, exclusions and consequential side effects;
- owner-gated actions and only the unknowns that change design, scope or safety.

Ask at most one focused requirements round, preferably as one compact set of
blocking questions. If repository evidence safely resolves the gap, state the
assumption and proceed. A clear request receives no ceremony. After this gate,
do not ask between routine stages; pause only for a real owner gate, changed
frozen input, scope-changing discovery or unrecoverable blocker.

Use `nobrainer-decide` when a consequential unresolved choice remains. Use
`nobrainer-spec-driven-development` only when a durable contract is justified by
architecture, public behavior, migration, difficult rollback, dependent phases
or resumability.

### 3. Build the complete `EXECUTION_MAP`

Before implementation, create a checkable TODO list for the whole known path to
acceptance. Keep it inline for ordinary work; persist it only when the task spans
sessions, is resumable/risky or the project already has a canonical tracker.
Before the first write, show the map in the working response or write it to the
named canonical tracker. Do not replace `EXECUTION_MAP` with a generic numbered
plan, hidden reasoning or a list of tools.

Every stage must contain:

```text
ID | OUTCOME | METHOD | OWNER_OR_SESSION | DEPENDENCIES | WRITE_SCOPE |
ACCEPTANCE_AND_EVIDENCE | PARALLEL_GROUP | OWNER_GATE | STATUS
```

Record the two independent control axes once for the run:

```text
CONTROL_MODE: BUDDY -> AUTOPILOT
SESSION_MODE: MAIN | MULTI_SESSION
AUTOMATION_CONTRACT: trigger | inputs | outputs | state owner | idempotence |
resume/checkpoint | retry budget | stop conditions | attention budget
```

`CONTROL_MODE` says how much owner interaction is required; `SESSION_MODE` says
where work executes. AUTOPILOT may stay in MAIN, while a BUDDY decision may use
an independent read-only specialist. Use these enum values literally and never
infer one axis from the other.

`METHOD` is exactly one primary owner: a NoBrainer skill, maintained project
capability, reviewed temporary skill or `DIRECT` when loading a skill adds no
value. A stage may invoke supporting tools, but one method owns its result.
Mark optional stages `NOT_NEEDED` with a reason; never hide them or manufacture
work to fill the map.

Every executable row must display its literal `METHOD`; a skill name mentioned
only in prose or topology is not assigned. The map is invalid while a known
acceptance step, correction loop, integration step or final evidence gate is
missing.

Keep the map compact without hiding work:

- use one row per independently auditable state transition, not per command,
  internal skill mode or tool activation;
- state shared owner gates, retry/attention budgets and global exclusions once;
- target 5-12 rows for an ordinary non-trivial task; exceed that only for
  genuinely distinct outputs, dependencies, writers or evidence gates;
- use one concise `NOT_NEEDED: <reason>` line for inapplicable optional methods;
- do not invoke Research for a stable locally testable fact, or SDD when explicit
  acceptance plus the execution map is already a sufficient durable contract.

Use the routing reference to assign at least these concerns when applicable:
research, writing, decision, specification, team design, session transport,
diagnosis, implementation, security, browser evidence, independent review,
verification and durable learning.

Invoke `nobrainer-team` when the map contains a real capability gap, two or more
independent units on the critical path, a valuable isolation boundary or an
independent review whose risk reduction exceeds coordination cost. Invoke
`nobrainer-dispatcher` when the approved map has multiple delegated work units,
a parallel group, dependency-aware batches or retries that need one scheduler.
It chooses only already-defined ready work; it does not invent tasks. Invoke
`nobrainer-sessions` for exact visible session creation, reuse, transport and
receive-audit. A coherent edit stays in MAIN; a clearly parallel plan should not
be serialized without a reason.

Any map that assigns a worker must first contain a `nobrainer-team` stage proving
the minimum roster and capability sources. For a scheduled queue, use exactly:

`Team -> Dispatcher SCHEDULE -> Sessions setup/delegate -> Dispatcher DISPATCH`

Dispatcher selects already-defined work, Sessions alone performs identity
preflight and transport, and Dispatcher commits `READY -> SENT` only from that
readback. After the worker reports, Sessions performs `RECEIVE_AUDIT` and
Dispatcher `RECONCILE` chooses the next scheduler transition. Do not add a second
Sessions preflight or transport stage. Without a justified dispatcher, Team may
lead directly to Sessions. Worker names alone do not satisfy this gate.

Default title is `<repo> | MAIN`; workers use `<repo> | <TASK_ID> <ROLE>`. Names
help navigation, while exact thread/host, checkout, task, scope and readback
establish identity.

### 4. `READY_GATE`

Enter `READY` only when the goal, frozen current state, complete execution map,
next safe stage/group, write scope, dependencies, acceptance, verifier, rollback,
owner gates and required capabilities are explicit. Unknown identity, dirty
overlap, stale input, lease conflict, missing required method or ambiguous
irreversible effect blocks execution.

`READY_GATE` fails if `CONTROL_MODE`, `SESSION_MODE` or the required map columns
are absent from the visible/canonical plan.

Run the design check:

```text
DESIGN_CHECK
  SIMPLEST_COMPLETE: PASS | FAIL
  KISS: PASS | FAIL
  YAGNI: PASS | FAIL
  DRY_STATE_OWNER: PASS | FAIL
  SOLID_BOUNDARIES: PASS | NOT_APPLICABLE | FAIL
  REUSED_MAINTAINED_CAPABILITY: YES | NO_WITH_REASON
  SPECULATIVE_SCOPE_REMOVED: YES | NO
  AI_SLOP_RISKS: NONE | <exact risk and action>
```

Route implementation stages through `nobrainer-build`; it operationalizes these
principles and rejects filler, invented claims, duplicate state, broad unrelated
refactors and test-only theatre.

For content, product or workflow deliverables, also freeze `CONTENT_QUALITY`:
purpose, audience, correctness sources, required completeness, coherent
structure/terminology and the target-human or target-workflow review. Polished
prose without usefulness evidence is not acceptance.

Route material user-facing prose through `nobrainer-writing` when drafting,
compression, voice or document structure is part of acceptance. Do not add a
Writing stage for a tiny answer that is already clear, specific and complete.

### 5. `AUTOPILOT`

Execute the approved map without routine check-ins. Activate one safe stage or
independent parallel group, update status from evidence, then continue. Use the
named skill or project method for each stage; do not silently substitute a
different owner.

AUTOPILOT includes ordinary file edits, commands, tests, bounded retries and
corrective work inside the approved scope. It does not expand permission.
Merge, deploy, publish, spend, delete, contact people, change credentials,
migrate data, mutate production or weaken safety controls remain explicit gates
at action time unless the owner already granted that exact authority.

On failure, preserve artifacts and blocker fingerprint. Retry only with new
evidence or a changed condition and within the declared budget. A timeout,
partial result, dead session, failed check or exhausted retry is not completion.

### 6. `VERIFY` and `RECEIVE_AUDIT`

Run fresh checks that prove every acceptance item at its actual layer. Static
validation, local runtime, deployed runtime, production behavior, external
delivery and user usefulness are different evidence levels.

For delegated work, invoke `nobrainer-sessions` receive-audit. Bind the report to
the exact session, host, checkout, commit, work unit, diff, evidence and released
lease before advancing. If Dispatcher owns the queue, return the audited result
to its `RECONCILE` mode before releasing dependencies. A worker's `FINISHED`,
exit code or `NEXT_ACTION` is unverified input, not routing authority.

Invoke `nobrainer-review` for the final closeout, adversarial bug hunt or release
gate justified by the map. Fixes route back through `nobrainer-build` and
invalidate earlier evidence for the changed path.

### 7. `LEARN`

Keep learning proportional after acceptance:

- discard transient task state;
- route an authorized durable preference, decision or verified fact to
  `nobrainer-wiki` mode `ADD`;
- route a repeated skill/prompt/control gap to `nobrainer-autoimprove` with a
  frozen failing scenario, baseline and holdout;
- update project instructions only when a durable missing rule caused measurable
  friction, using one scoped reversible diff.

Do not infer a permanent profile from one interaction or let improvement delay
the requested result.

## Correction hooks

Correction happens immediately, not only at the final learning close:

- `OWNER_DECISION_CHANGED`: update the canonical requirement/decision, mark the
  old value superseded, move affected not-started `READY` rows to `STOPPED`,
  keep dependants `PENDING` or `BLOCKED`, invalidate their evidence, then
  rebuild under a new plan fingerprint before recomputing readiness;
- `AGENT_ERROR_CORRECTED`: fix the current result, classify a minimal prevention
  candidate, persist it only as `LEARNING_WRITE_POLICY` permits, and route
  repeatable behavior gaps to `nobrainer-autoimprove`;
- `REVIEW_FAILED`: keep the stage open, route the verified finding back to
  `nobrainer-build`, rerun affected tests, repeat the review with fresh proof,
  then run a fresh `RECEIVE_AUDIT` that binds all current evidence before
  acceptance;
- `REPEATED_DEFECT`: stop blind retries and route to `nobrainer-rca` with the
  prior fingerprint and evidence.

One correction is not permission to infer a permanent user profile. Wiki writes
remain sourced, classified and authorized; project instruction changes must be
small, testable and reversible. The detailed store ownership and invalidation
rules are in the correction-hooks reference.

## Final response

Lead with the delivered outcome. Report execution-map status, skills/methods and
sessions actually used, acceptance evidence, unresolved uncertainty, owner gate
if any, rollback and one next action. Stop when the map is complete or at the
first real gate; never manufacture a successor after the outcome is accepted.
