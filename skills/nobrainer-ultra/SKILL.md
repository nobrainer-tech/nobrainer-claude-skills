---
name: nobrainer-ultra
description: "Use when the owner says nb-ultra, nb-flow or nb-workflow; take one non-trivial task from brief requirements through concise progress, bounded execution, recovery and evidence audit, or set up or repair that workflow."
---

# NoBrainer Ultra

Turn one owner request into the smallest complete verified outcome the current
project and runtime can deliver. Hide orchestration mechanics from the owner;
surface scope, progress, proof, real decisions and blockers.

Read [references/routing.md](references/routing.md) before selecting methods.
For setup, upgrade, installation or repair, also read
[references/setup.md](references/setup.md). Read
[references/correction-hooks.md](references/correction-hooks.md) only after an
owner decision changes, the agent is corrected or review fails. Read
[references/long-run-state.md](references/long-run-state.md) only when the
detailed-ledger gate below passes.

## Choose the smallest workflow

A mechanical, reversible task remains direct. Use Ultra when the outcome is
non-trivial because scope, dependencies, risk, proof layers, resumability or
specialist routing matter.

Default to one primary agent in the current session. Add a worker only for a
bounded independent unit with a measurable latency, isolation or independent
judgment benefit. More available agents is not evidence that a team helps.

The ordinary lifecycle is:

`DRIFT_CHECK -> BUDDY -> SCOPE -> AUTOPILOT -> VERIFY -> RECEIVE_AUDIT -> LEARN`

These names describe internal control points. Do not print a state-machine form
to the owner.

## `DRIFT_CHECK`: establish current truth

Read the repository root, nearest instructions, dirty state, branch/worktree,
current plan/spec, callers, tests, runtime and available capabilities. Preserve
unrelated work. Prior summaries, titles, wiki pages and worker reports are
context, not current runtime proof.

Query an existing wiki only for a decision, constraint or lesson that can change
this task. Research a fact when it is current, external, niche, uncertain,
high-stakes or source-attributed.

`PROBLEM_GATE`: start with the literal failure, current local evidence and the
smallest reproducer. Check related wiki decisions when available. Use current
primary-source internet research only when the remedy depends on a current,
external, niche, uncertain or high-stakes fact. A stable local syntax, import,
test or configuration error does not need browsing before the next local
diagnostic. If required research is inaccessible, stop at `RESEARCH_BLOCKED`.

## `BUDDY`: clarify once

Use one focused requirements round only when the answer changes scope,
architecture, safety or acceptance. Otherwise state the smallest safe assumption
and continue. Establish:

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

`Expected files` names the predicted write surface and why each file belongs; if
inspection proves another file necessary, update scope before editing it.
`Untouched` protects unrelated dirty work and compatibility boundaries.
`Done clean` means actual files match the approved scope, proof passes,
placeholders and speculative layers are absent, and final status has no surprise.
If inspection or execution is explicitly excluded, keep the plan provisional.
Default to at most 160 words: one outcome sentence, at most three scope bullets, the compact Progress view,
at most three proof bullets and one next action. Do not announce skill use, claim planning is complete, or enumerate
implementation phases or possible mechanisms. Do not invent unseen schemas, endpoints, state machines, storage or polling;
name only required boundaries and proof, and mark exact paths and methods as pending inspection.

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

Update it after scope is frozen, at meaningful transitions, on a blocker and at
closeout. Do not narrate every command or print specialist forms. The checklist
is a view of the canonical TODO owner, not a second ledger. A worker report,
exit code or summary cannot mark an item complete. A stale summary never
authorizes a successor.

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

The safe next step is ready only when current state, write scope, dependencies,
proof, rollback, owner gates and required capability are known. Unknown identity,
dirty overlap, stale input, missing verifier or ambiguous irreversible effect
blocks the write.

Choose the least complex capable method. Route implementation through
`nobrainer-build`. Load other skills only for their active boundary:

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

Specialist report schemas are audit inputs. Translate them into natural language
for the owner: outcome, material evidence, uncertainty, gate and next action.
Do not dump all-caps status forms into ordinary conversation.

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
- `REPEATED_DEFECT`: stop blind retries and route the frozen failure to RCA.

Detailed canonical-store rules live in the correction-hooks reference.

## `LEARN` and close

Keep learning proportional. Discard transient state. Persist only durable,
sourced, authorized and non-secret knowledge. Route a repeatable behavior gap to
`nobrainer-autoimprove` only with a frozen baseline and holdout; a null result
is valid.

Lead the final response with the delivered outcome. Include changed scope,
fresh checks and proof layer, unresolved uncertainty, rollback, owner gate if
any, and one next action. Do not repeat internal forms or invent follow-up work
after acceptance.
