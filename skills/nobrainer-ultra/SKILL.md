---
name: nobrainer-ultra
description: "Use when the owner says nb-ultra, ultracode, or asks for the fastest high-quality execution of a non-trivial project task that may require requirements discovery, durable planning, named sessions, guarded autonomy, or workflow reconciliation."
---

# NoBrainer Ultra

Turn one owner request into the smallest workflow that can deliver it quickly,
correctly, and visibly. This skill owns lifecycle and routing. It does not copy
the technical methods of Superpowers or domain skills.

## Lifecycle

Run this state machine on every invocation, including after a previous setup:

`DRIFT_CHECK -> BUDDY -> READY_GATE -> AUTOPILOT -> VERIFY -> RECEIVE_AUDIT`

### 1. `DRIFT_CHECK`

Read the actual repo root, nearest instructions, dirty state, branch/worktree,
current goal/spec/plan, tests, verifiers, durable knowledge, session registry,
and available skill/runtime capabilities. Compare them with the requested
outcome. Classify drift as `CLEAN`, `RECONCILABLE`, `OWNER_DECISION`, or
`BLOCKED`. Never overwrite unrelated work or trust stale titles/status.

Read [references/routing.md](references/routing.md) before choosing artifacts or
dependent skills.

### 2. `BUDDY`

This is a short requirements gate, not an ongoing chat mode. Establish:

- observable outcome and audience;
- acceptance evidence;
- scope and exclusions;
- risk envelope and owner-gated actions;
- only the unresolved assumptions that change architecture, scope, or safety.

Reuse a fresh approved spec. Invoke the official Superpowers brainstorming
capability only when unresolved requirements or design choices can materially
change scope, architecture, safety, or acceptance. Ask at most one focused
round; infer safe details from repository evidence. A clear bounded task does
not require brainstorming ceremony.

### 3. Goal, spec, plan, and topology

Every run has a logical goal and plan. Persist them only when work is resumable,
multi-session, architectural, risky, or expensive to misinterpret.

- Use `nobrainer-spec-driven-development` when a durable spec is justified.
- Use `nobrainer-sessions` when visible handoff, isolation, resume, or a warm
  specialist outweighs coordination cost.
- Use `nobrainer-decide` for a consequential unresolved choice.
- Use `nobrainer-wiki` only for durable knowledge that should outlive tasks.

Default session title: `<repo> | MAIN`. Do not create workers before bounded
work units exist. A coherent task may stay in MAIN; hidden subagents are not a
substitute for requested visible sessions.

### 4. `READY_GATE`

Enter `READY` only when the goal, current state, acceptance, next work unit,
write scope, dependencies, verifier, rollback, owner gates, and session mode are
explicit. Required capabilities must pass readback. Unknown identity, dirty
scope, stale inputs, lease conflict, or ambiguous irreversible effects block
execution.

### 5. `AUTOPILOT`

Execute the approved scope without asking between routine steps. Use the
official Superpowers capability appropriate to the phase: planning, worktrees,
TDD, debugging, execution, review, or verification. Record rulings and evidence.

AUTOPILOT never implies permission to merge, deploy, publish, spend, delete,
change credentials, weaken safety controls, or mutate production. Those remain
owner gates at action time.

### 6. `VERIFY` and `RECEIVE_AUDIT`

Run fresh checks that prove acceptance in the target workflow. A worker report,
exit code, queued message, or `FINISHED` label is only audit input. For delegated
work, invoke `nobrainer-sessions` receive-audit and bind evidence to the exact
session, checkout, commit, scope, and lease before advancing.

## Final response

Lead with the outcome. Report lifecycle state, selected artifacts/sessions,
evidence, unresolved uncertainty, owner gate if any, one next action, and exact
rollback. Stop when complete or at the first real gate; never create an
unbounded continuation loop.
