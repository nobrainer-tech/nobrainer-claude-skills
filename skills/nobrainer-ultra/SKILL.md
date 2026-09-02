---
name: nobrainer-ultra
description: "Use when the owner says nb-ultra, nb-flow or nb-workflow; take one non-trivial task from brief requirements through concise progress, bounded execution, recovery and evidence audit, or set up or repair that workflow."
---

# NoBrainer Ultra

Turn one owner request into the smallest complete verified outcome the current
project and runtime can deliver; hide orchestration mechanics from the owner and
surface scope, progress, proof, decisions and blockers.

Read [references/routing.md](references/routing.md) before selecting methods. For
setup, upgrade, installation or repair, also read [references/setup.md](references/setup.md).
Read [references/correction-hooks.md](references/correction-hooks.md) only after
an owner decision changes, correction or review failure; read [references/long-run-state.md](references/long-run-state.md) only when its gate passes.

## Choose the smallest workflow

### Quick path for small changes

Use it for one coherent, reversible edit with obvious acceptance and no authentication,
secrets, data/production mutation, external side effect, architecture, migration or dependency decision.

1. Inspect the actual checkout, instructions, dirty state and nearest caller/test.
2. Edit only scoped files; run the nearest deterministic check and `git diff --check`.
3. Read back diff/status; report outcome, proof, uncertainty and rollback.

Skip requirements, ledger, team/dispatcher/sessions and independent review;
escalate to the full Ultra lifecycle when scope, risk, proof or an owner decision
expands; quick path never bypasses an owner gate.

Default to one primary agent. Add a worker only for a bounded independent unit with measurable latency, isolation or independent-judgment benefit; more agents are not evidence that a team helps.

The ordinary lifecycle is `DRIFT_CHECK -> BUDDY -> SCOPE -> AUTOPILOT -> VERIFY -> RECEIVE_AUDIT -> LEARN`; these are internal control points, not an owner-facing state machine.

## `DRIFT_CHECK`: establish current truth

Read the repository root, instructions, dirty state, branch/worktree, plan/spec,
callers, tests, runtime and capabilities; preserve unrelated work. Prior summaries,
wiki pages and worker reports are context, not proof. Query an existing wiki only for
a decision or lesson that can change this task. Research current, external, niche,
uncertain, high-stakes or source-attributed facts. For large documents or data,
and large repositories, inspect structure first, then read selected contracts in full and
relevant ranges; respect the context budget and name any unread required surface instead of implying coverage.

`PROBLEM_GATE`: start with the literal failure and local evidence; do not infer that
a documented command produced the failure. If the invocation is unknown, name reproduction
 from the repository root first; simulation-only request forbids execution, not naming that
 next diagnostic action. Only then propose path, dependency or configuration changes. Check
related wiki decisions. Use current primary-source research only when the remedy
depends on external, niche, uncertain or high-stakes facts; inaccessible research means
stop at `RESEARCH_BLOCKED`.

## `BUDDY`: clarify once

Use one focused requirements round only when scope, architecture, safety or acceptance
depends on an answer repository evidence cannot resolve. Current code, schema, tests
or conventions should settle implementation details; do not make them owner questions. Establish:

- observable outcome, audience and quality bar;
- target-workflow proof;
- exclusions and consequential side effects;
- owner-gated actions;
- unresolved choices that materially affect the design.

Use `nobrainer-decide` for a consequential choice among real alternatives.
Use `nobrainer-spec-driven-development` only when a maintained contract pays
for itself through architecture, public behavior, migration, difficult rollback,
dependent phases or resumability.

## Scope the minimum sufficient change

Before the first non-trivial write, resolve this compact contract. Keep it in the
canonical plan; show only the parts the owner needs to inspect.

```text
Outcome:
Non-goals:
Expected files:
Proof:
Untouched:
Minimum solution:
Test decision: EXISTING | NEW_REQUIRED | NOT_NEEDED — reason
Done clean:
```

`Outcome` is the portable goal; `Proof` plus `Done clean` are the definition of done. `Expected files`
predict scope; `Untouched` protects unrelated work and compatibility; update scope
before expanding. `Done clean` requires matching scope, passing proof, no placeholders
or surprises; excluded inspection stays provisional.
When the owner requests goal/DoD, show every field above and state the detailed-ledger decision.
Create a host-native goal after scope is frozen and require goal readback; the canonical
plan supersedes stale goal text after correction.
Default to at most 160 words: one outcome sentence, three scope bullets, compact
Progress, three proof bullets and one next action. Do not add a repetitive
skill/mode preamble or planning claim; avoid mechanism lists and invent unseen schemas, endpoints, state machines,
storage or polling; name required boundaries/proof and mark exact paths/methods
pending inspection.

Do not add a dependency, compatibility layer, fallback stack, worker, skill or
test without an acceptance need or demonstrated risk. A new shared abstraction
needs two real current callers or an explicit contract that requires it; a
hypothetical future caller is not enough.

Use a short checkable plan ordered by outcomes, not tools. One canonical TODO
owner may be the host plan, a repository tracker or the current response.

## Show human progress

For ordinary single-session work, show only a compact update:

```text
Progress
- [x] Scope and acceptance are clear
- [>] Inspecting the current caller and tests
- [ ] Implement and verify
Next: open the named caller and its existing test
```

Update it after scope is frozen, at a material transition, blocker, safety gate,
new evidence and closeout. Run tools without announcing the next command when
the host permits; otherwise emit its shortest useful scope or evidence sentence.
Never repeat the plan, unchanged state or already reported proof. Preserve exact
commands, errors, numbers and negations; expand when brevity risks ambiguity.
Persisted code, docs, commits and third-party messages use normal complete prose.
The checklist views the canonical TODO; worker reports, exit codes and summaries
cannot advance it. A stale summary never authorizes a successor.
Use a detailed ledger only when at least one condition is true:

- work crosses sessions or must resume safely after context loss;
- dependencies, multiple writers or a delegated queue control readiness;
- a consequential external effect requires auditable gates and recovery;
- the owner explicitly requests a durable execution record.

Otherwise the detailed ledger is unnecessary ceremony; a multi-component task
that still fits one coherent session does not pass this gate. When the gate passes,
use [references/long-run-state.md](references/long-run-state.md) and keep the
owner-facing Progress checklist concise.

## Readiness and method routing

The safe next step is ready only when current state, write scope, dependencies, proof, rollback,
owner gates and required capability are known. Unknown identity, dirty overlap, stale input, missing verifier or ambiguous irreversible effect blocks the write.

Choose the least complex capable method; route implementation through `nobrainer-build`.
When another skill owns a stage, load its canonical body and required references before
planning. Loading method context is not task execution; a routing-table line or remembered
summary is insufficient. Load specialists only:

- `nobrainer-research` for decision-relevant external uncertainty;
- `nobrainer-writing` for material user-facing prose;
- `nobrainer-security` for trust boundaries;
- `nobrainer-browser` for rendered behavior or trace evidence;
- `nobrainer-rca` after repeated or causally unclear failure;
- `nobrainer-review` when independent closeout adds material confidence;
- `nobrainer-team`, `nobrainer-dispatcher` and `nobrainer-sessions` only for
  justified roles, a real delegated queue and exact transport/identity.

Do not add Research for a stable locally testable fact, SDD for an explicit
single-session change, Review for a mechanical typo, or a worker for work the
primary agent can complete coherently.

## `AUTOPILOT`: execute the bounded scope

After readiness, continue without routine check-ins through approved edits,
commands, focused tests, broader verification and bounded corrective work. Stop
for a changed frozen input, scope-changing discovery, unrecoverable blocker or
real owner gate.

Autonomy does not expand authority. Merge, deploy, publish, spend, delete,
contact people, change credentials, migrate data, mutate production or weaken
safety controls remain explicit gates unless the owner already authorized that
exact action.

Retry only when evidence or a condition changes and within a declared budget.
A timeout, partial result, dead session, failed check or exhausted retry is not
completion.

Specialist schemas are audit inputs. Report once: outcome, decisive evidence,
remaining uncertainty or gate, and next action. Do not dump status forms.

## `VERIFY` and `RECEIVE_AUDIT`

Prove every acceptance item at its actual layer. Static validation, local
runtime, deployed runtime, production behavior, external delivery and user
usefulness are different evidence levels.

For delegated work, use `nobrainer-sessions` `RECEIVE_AUDIT`. Bind the
report to the exact session, host, checkout, commit, work unit, diff, proof and
released writer state. If Dispatcher owns a queue, return the audited result to
its reconcile mode before releasing dependencies.

Invoke `nobrainer-review` for a justified adversarial or release closeout.
A verified finding returns to `nobrainer-build`; changed work invalidates old
proof and must be re-tested and re-reviewed.
## Correction hooks

Apply corrections immediately:

- `OWNER_DECISION_CHANGED`: supersede the old decision, move affected
  not-started `READY` rows to `STOPPED`, block dependants and invalidate
  only their evidence before re-planning.
- `AGENT_ERROR_CORRECTED`: fix the active result and classify one minimal
  prevention candidate under the configured learning policy.
- `REVIEW_FAILED`: keep the item open, route the finding to Build, rerun
  affected proof and repeat Review with fresh evidence.
- `CANDIDATE_REJECTED`: preserve the champion, close that experiment rather than
  the owner outcome, then try one smallest high-leverage change against a fresh holdout or report the concrete blocker.
- `REPEATED_DEFECT`: stop blind retries and route the frozen failure to RCA.
Detailed canonical-store rules live in the correction-hooks reference.
## `LEARN` and close

Keep learning proportional. Discard transient state. Persist only durable,
sourced, authorized and non-secret knowledge. Route a repeatable behavior gap to
`nobrainer-autoimprove` only with a frozen baseline, calibrated evaluator
outside candidate write scope and sealed holdout; a null result is valid.
Lead the final response with the delivered outcome. Include changed scope,
fresh checks and proof layer, unresolved uncertainty, rollback, owner gate if
any, and one next action. Do not repeat internal forms or invent follow-up work
after acceptance.
