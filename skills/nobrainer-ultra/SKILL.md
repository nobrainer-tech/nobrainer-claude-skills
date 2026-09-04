---
name: nobrainer-ultra
description: "Use when the owner says nb-ultra, nb-flow or nb-workflow; take one non-trivial task from brief requirements through concise progress, bounded execution, recovery and evidence audit, or set up or repair that workflow."
---

# NoBrainer Ultra

Deliver the smallest verified outcome; surface scope, proof and blockers.

Read [references/routing.md](references/routing.md) and [references/model-routing.md](references/model-routing.md) before selecting methods; setup, upgrade, installation or repair also require [references/setup.md](references/setup.md).
Read [references/correction-hooks.md](references/correction-hooks.md) after owner decision changes, correction or review failure; read [references/long-run-state.md](references/long-run-state.md) only when its gate passes.

## Choose the smallest workflow

### Quick path for small changes

Use one coherent, reversible edit with acceptance and no authentication, secrets,
data/production mutation, external effect, architecture, migration or dependency
decision. Public contract, routing, workflow or portfolio changes use full
lifecycle and coherence gate.

1. Inspect the actual checkout, instructions, dirty state and nearest caller/test.
2. Edit only scoped files; run the nearest deterministic check and `git diff --check`.
3. Read back diff/status; report outcome, proof, uncertainty and rollback.

Skip requirements, ledger, team/dispatcher/sessions and independent review;
escalate to the full Ultra lifecycle when scope, risk, proof or owner decision expands;
quick path never bypasses an owner gate.

Default to one agent; add workers only when latency, isolation or judgment earns
their cost.

Lifecycle: `DRIFT_CHECK -> BUDDY -> SCOPE -> AUTOPILOT -> VERIFY -> RECEIVE_AUDIT -> LEARN`; these are internal controls.

Bounded turns: run `SESSION_HEALTH_GATE` at START, AFTER_COMPACTION,
MATERIAL_TRANSITION and BEFORE_CLOSEOUT. `WARNING` checkpoints and restricts
dispatch; a hard limit persists the durable goal, writes a compact handoff, then
uses a verified host clear or `END_TURN`; automatic
rotation is forbidden. `task_complete` is not `RUNTIME_RELEASE`. No legal
`READY` row means checkpoint + `OWNER_DECISION_REQUIRED`.

## `DRIFT_CHECK`: establish current truth

Read root, instructions, dirty state, branch/worktree, plan/spec, callers, tests, runtime and capabilities; preserve unrelated work. Prior summaries, wiki and worker reports are context, not proof; query wiki only for a decision or lesson that can change this task.
Research current, external, niche, uncertain, high-stakes or attributed facts. For large documents or data and repositories, inspect structure first, then read selected contracts in full and relevant ranges; respect context budget and name unread required surface.

`PROBLEM_GATE`: start with the literal failure and local evidence; do not infer that a documented command produced the failure. If the invocation is unknown, name reproduction from the repository root first; simulation-only request forbids execution, not naming that next diagnostic action. Only then propose path, dependency or configuration changes. Check related wiki decisions. Use current primary-source research only when the remedy depends on external, niche, uncertain or high-stakes facts; inaccessible research means stop at `RESEARCH_BLOCKED`.

## `BUDDY`: clarify once

Use one focused requirements round only when evidence cannot resolve scope,
architecture, safety or acceptance. Code, schema, tests or conventions settle it;
do not make them owner questions. Establish:

- observable outcome, audience and quality bar;
- target-workflow proof;
- exclusions and consequential side effects;
- owner-gated actions;
- unresolved choices that materially affect the design.

Use `nobrainer-decide` for consequential choices among real alternatives.
Use `nobrainer-spec-driven-development` only when a maintained contract pays for architecture,
public behavior, migration, rollback, dependent phases or resumability.

## Scope the minimum sufficient change

Before the first non-trivial write, resolve this compact contract. Keep it in the
canonical plan; show only fields the owner needs to inspect.

```text
Outcome:
Non-goals:
Expected files (PUBLIC_SURFACE):
Proof:
Untouched:
Minimum solution:
Test decision: EXISTING | NEW_REQUIRED | NOT_NEEDED — reason
Done clean:
```

`Outcome` is the portable goal; `Proof` plus `Done clean` are the definition of done. `Expected files`
predict scope; `Untouched` protects compatibility; update scope before expanding.
`Done clean` requires matching scope, passing proof, no placeholders or surprises;
excluded inspection stays provisional.
`PUBLIC_SURFACE` is mandatory: set `UPDATE` and map affected README/docs/templates/assets/flow, or set `PUBLIC_SURFACE: NOT_NEEDED` with a reason; public contract, routing or workflow changes require fresh SVG + README Mermaid readback.
When the owner requests goal/DoD, show every field above and state the detailed-ledger decision.
For work that passes the detailed-ledger gate, persist the goal in an existing
Markdown tracker or task-local Markdown `GOAL_FILE`; it is canonical across clears,
compactions and sessions. Mirror it into a host-native goal after scope freezes
and require goal readback from both. The file supersedes stale transcript text.
Default to at most 160 words: outcome, scope, Progress, proof and next action.
Do not add a repetitive
skill/mode preamble or planning claim; avoid mechanism lists and invent unseen
schemas, endpoints, state machines, storage or polling; name required
boundaries/proof and mark exact paths/methods pending inspection.

Do not add a dependency, compatibility layer, fallback stack, worker, skill or
test without an acceptance need or demonstrated risk. A shared abstraction needs
two real current callers or an explicit contract; a future caller is
not enough.

Use a short plan ordered by outcomes. One canonical TODO owner may be the host
plan, repository tracker or current response.

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

Proceed only when state, scope, dependencies, proof, rollback, gates and capability are known; unknown identity, overlap, stale input, missing verifier or ambiguous irreversible effect blocks writing.

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

Specialist schemas are audit inputs. Report outcome, evidence, uncertainty and
next action. Do not dump forms.

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
`VERIFY` fails closeout when an affected public surface lacks its update or readback.
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

Discard transient state. Persist only durable,
sourced, authorized and non-secret knowledge. Route a repeatable behavior gap to
`nobrainer-autoimprove` only with a frozen baseline, calibrated evaluator
outside candidate write scope and sealed holdout; a null result is valid.
Lead the final response with the delivered outcome. Include changed scope,
fresh checks and proof layer, unresolved uncertainty, rollback, owner gate if
any, and one next action. Do not repeat internal forms or invent follow-up work
after acceptance.
