# Long-run state and recovery

Read this reference only after Ultra's detailed-ledger gate passes. It preserves
safe resume and delegated coordination without forcing machine ceremony into
ordinary single-session work.

## One canonical ledger

Use the project's existing durable tracker when suitable. Otherwise create one
small task-local artifact. It is the only mutable owner of execution state;
specifications define required truth, reports provide evidence, and the wiki
stores durable knowledge.

Record the run boundary once:

```text
Run:
Frozen request/spec and fingerprint:
Base checkout and commit:
State owner:
Integration owner:
Owner gates:
Stop conditions:
```

Use one row per independently auditable outcome, not per command:

```text
ID | Outcome | Method | Owner/session | Dependencies | Write scope |
Proof | Owner gate | Status
```

`Method` is one primary owner: a NoBrainer skill, maintained project capability,
reviewed temporary capability or `DIRECT` for a truly mechanical step. Known
implementation, verification, correction, integration and closeout work must
appear before execution starts.

Useful states are `PENDING`, `READY`, `RUNNING`, `BLOCKED`, `REPORTED`,
`AUDITED`, `ACCEPTED`, `CORRECTION_REQUIRED` and `STOPPED`. A report or green
exit code cannot move a row to `ACCEPTED` without current proof.

The owner-facing Progress checklist is only a view of this ledger. Update both
from the same evidence at meaningful transitions.

## Recovery card

For unattended or resumable work, record:

```text
Trigger and frozen inputs:
Expected outputs:
Checkpoint and resume command/path:
Idempotence key or duplicate-prevention rule:
Retry budget and blocker fingerprint:
Evidence location:
Rollback:
Attention budget and urgent owner events:
```

Do not invent a retry path. If a step cannot be safely resumed or repeated,
state that before starting it and require the appropriate checkpoint or owner
gate.

At session start or after compaction, reconcile the exact checkout, base/HEAD,
dirty state, ledger fingerprint, active sessions/writers, last accepted proof
and next `READY` row. A stale summary never authorizes a successor.

## Team, queue and transport

Use one primary MAIN session. Before assigning any worker:

1. `nobrainer-team` proves the minimum roster and bounded work units.
2. If several delegated units form a queue, `nobrainer-dispatcher` computes the
   ready set and bounded batch.
3. `nobrainer-sessions` alone creates/reuses exact sessions, checks identity and
   writer state, and sends each bounded unit.
4. Dispatcher may record `READY -> SENT` only from that transport readback.

The canonical queued transition is:

`Team -> Dispatcher SCHEDULE -> Sessions setup/delegate -> Dispatcher DISPATCH`

Sessions alone performs identity preflight and transport. Dispatcher never
duplicates that send or treats a planned assignment as delivered.

A worker receives one outcome, inputs, exact write scope, proof, stop conditions
and report destination. It never chooses a successor.

When a worker reports, Sessions performs `RECEIVE_AUDIT` against the exact
session, host, checkout, commit, diff, tests, evidence and released writer state.
If Dispatcher owns the queue, its reconcile step consumes that audited result
before releasing dependencies.

## Failure and correction

- Unknown dependency, identity, write ownership or lease state is `BLOCKED`.
- A changed owner decision supersedes the old requirement, stops affected
  not-started rows and invalidates dependent proof.
- A verified review finding becomes `CORRECTION_REQUIRED` and returns to Build.
- A repeated blocker keeps one stable fingerprint; retry only after a changed
  condition or new evidence.
- Timeout, dead session, partial output and retry exhaustion preserve the row as
  incomplete.

Close the ledger only when every required row is `ACCEPTED` or explicitly
`STOPPED` by a superseding owner decision, all writers are released, final proof
is current and rollback is still intelligible.
