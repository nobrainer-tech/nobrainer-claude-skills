# NoBrainer Sessions protocol

Adapt names and paths to the project. Reuse an existing source of truth instead
of creating duplicate status files. Unknown values block dispatch; never ship
placeholders in a live prompt.

## Durable boundaries

Keep four concepts distinct even if a small project stores them in fewer files:

| Concept | Contains | State writer |
|---|---|---|
| master plan | outcomes, task graph, dependencies, acceptance, gates | owner or MAIN |
| execution state | current task, registry, attempt, lease, evidence pointers | MAIN |
| workflow protocol | stable roles, transitions, prompt/report formats | owner or MAIN |
| reports and evidence | task-bound reports, manifests, logs, test output | worker writes task evidence; MAIN indexes it |

Do not put current IDs, hashes, leases, or blocker history into the stable
protocol. Do not copy execution status into a wiki.

## Session registry row

```text
TITLE: <repo> | <MAIN|ROLE|TASK_ID>
HARNESS: <client and version>
THREAD_ID: <exact ID>
HOST_ID: <exact host ID or verified NONE>
STATUS: IDLE | ACTIVE | BLOCKED | CLOSED | UNKNOWN
REPOSITORY: <canonical repository identifier>
CHECKOUT: <absolute checkout/worktree path or harness-native identifier>
BRANCH: <branch or NONE>
BASE_COMMIT: <commit or NONE>
HEAD_COMMIT: <commit or NONE>
ROLE: MAIN | <bounded role>
TASK_ID: <task or NONE>
WRITE_SCOPE: <exact files/systems or READ_ONLY>
ISOLATION: SHARED_READ_ONLY | ISOLATED_WORKTREE | OTHER_VERIFIED
LEASE: FREE | HELD | RELEASED | CONFLICT | UNSUPPORTED
FENCING_SUPPORTED: YES | NO
FENCING_EPOCH: <monotonic token or NONE>
LAST_READBACK: <UTC timestamp and evidence pointer>
```

## Delegating prompt

```text
ROLE:
You are the worker for TASK_ID=<ID>. You own only <bounded scope>. You are not
MAIN. Do not select, send, or start a successor.

OUTCOME:
Produce <one observable result>. Success means <independent acceptance>.

EXCLUDED_SCOPE:
- Do not change <files, systems, decisions, production, credentials, publishing,
  destructive operations, or safety controls outside scope>.
- Do not expand scope without an owner or MAIN decision.

IDENTITY:
- REPOSITORY: <identifier>
- CHECKOUT: <exact checkout/worktree>
- THREAD_ID: <worker ID>
- HOST_ID: <worker host or verified NONE>
- TASK_ID: <ID>
- METHOD: <literal owning skill or project capability>
- WRITE_SCOPE: <scope>

CANONICAL_INPUTS:
- PLAN: <path or canonical tracker reference>
- EXECUTION_STATE: <path or canonical state reference>
- REPORT_PATH: <task-bound path>
- FROZEN_INPUTS: <hashes/versions or NONE>
- VERIFIER: <command or NONE>

EXPECTED_STATE:
- ACTIVE_TASK: <ID>
- PREDECESSOR: <state>
- ALLOWED_SUCCESSOR: <state after MAIN audit>
- LEASE: <owner, status, acquisition evidence>
- FENCING_EPOCH: <token or NONE>

START_GATE:
1. Read repository instructions and canonical inputs.
2. Verify identity, CHECKOUT, task, scope, current HEAD and expected state.
3. Verify frozen inputs, writer isolation and relevant preflight check.
4. Immediately before the first write, acquire LEASE according to the project
   rule and record its owner, time and evidence. If it is held, conflicting,
   unsupported where required, or changed after preflight, stop without writing.
5. Record a start manifest after the lease check and before the first write.
6. Stop on any mismatch; do not repair canonical state yourself.

WORK_UNIT:
- <one bounded action>
- METHOD: <literal owning skill or project capability>
- ACCEPTANCE: <measurable condition>
- REQUIRED_EVIDENCE: <diff, tests, verifier, build/runtime, review>

CLOSE_GATE:
1. Record changed paths and final commit/state.
2. Run required tests/verifier/build/runtime and preserve raw output.
3. Review scope, quality, secrets, side effects and rollback.
4. Write close-gate evidence and release LEASE if held.
5. Send exactly one final report to MAIN and end the turn.

ON_FAILURE:
Stop this task. Preserve evidence and checkpoint. Do not start a successor.
Release LEASE when safe. Recommend one bounded remediation.

HANDOFF:
- COORDINATOR_THREAD_ID: <exact MAIN ID>
- COORDINATOR_HOST_ID: <exact host or verified NONE>
- If transport has no receipt, set HANDOFF_STATUS: NOT_SENT.

FINAL_REPORT:
RESULT: FINISHED | BLOCKED | FAILED | OWNER_DECISION_REQUIRED |
  INPUT_CHANGED | LEASE_CONFLICT
HANDOFF_STATUS: SENT | NOT_SENT
HANDOFF_MESSAGE_ID: <receipt ID or NONE>
THREAD_ID: <worker ID>
HOST_ID: <worker host or verified NONE>
REPOSITORY: <identifier>
CHECKOUT: <checkout/worktree>
TASK_ID: <ID>
METHOD: <literal owning skill or project capability>
BASE_COMMIT: <commit or NONE>
HEAD_COMMIT: <commit or NONE>
WRITE_SCOPE: <scope>
CHANGES: <paths or NONE>
TESTS: <commands, result, raw evidence pointer>
VERIFIER: <command, result, evidence pointer>
BUILD_RUNTIME: <result or NOT_RUN with reason>
QUALITY_REVIEW: <result/evidence or NOT_APPLICABLE>
START_MANIFEST: <path/reference>
CLOSE_EVIDENCE: <path/reference>
BLOCKER_FINGERPRINT: <stable value or NONE>
ATTEMPT_NO: <integer>
NEXT_ACTION: <one recommendation>
ROLLBACK: <exact procedure>
LEASE: RELEASED | NOT_HELD | UNSUPPORTED | NOT_RELEASED_WITH_REASON
FENCING_EPOCH: <token or NONE>
```

## RECEIVE_AUDIT checklist

MAIN verifies from independent readback:

1. expected session and completed turn;
2. registry identity, CHECKOUT, base and HEAD;
3. task, allowed transition, write scope and changed paths;
4. frozen inputs, start manifest and close evidence;
5. reproducible test, verifier, build/runtime and quality evidence;
6. no hidden writer, task, side effect, secret, or scope expansion;
7. lease passes: `RELEASED`, or independently verified `NOT_HELD` or
   `UNSUPPORTED`; `NOT_RELEASED_WITH_REASON` always blocks advancement; when
   fencing is supported, the fencing token must also be valid;
8. transport receipt or an honest `NOT_SENT`.

Only MAIN updates canonical execution state. A worker's `NEXT_ACTION` is a
recommendation, not a command.

## Retry and recovery record

```text
ATTEMPT_NO: <integer>
LAST_BLOCKER_FINGERPRINT: <stable fingerprint>
LAST_BLOCKER_EVIDENCE: <path/reference>
NEW_EVIDENCE_REQUIRED: YES | NO
RECOVERY_OWNER: <owner/session>
RETRY_BUDGET: <integer>
CHECKPOINT: <path/reference or NONE>
ROLLBACK: <procedure>
ROLLBACK_READBACK: <evidence pointer>
USER_REMEDIATION: <one action or NONE>
```

Do not repeat an unchanged failure after the retry budget or without new
evidence. A timeout, partial output, dead session, or exhausted retry is not
success.
