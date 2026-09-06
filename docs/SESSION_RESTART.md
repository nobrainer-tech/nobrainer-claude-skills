# Adaptive session restart

The v1.8.1 source includes this portable protocol and dated session titles. The
existing v1.8.0 tagged archive remains unchanged and is the rollback anchor.

Tell Flow: “Enable automatic session-restart for this task. Keep progress in
files and archive the old conversation only after the successor takes over.”
That grants standing consent within the task. The current model and effort stay
as selected. Ask for a daily policy only if you want session age considered too.

Flow checks quietly after useful milestones. It estimates whether carrying less
context through the next small unit repays checkpoint and startup overhead.
Compaction count and elapsed time trigger assessment, not automatic rotation.
It preserves decisions, acceptance, authorized scope, dirty work, evidence and
the next action. A successful restart gets one brief notification; routine
checks do not add chat noise.

There is no fixed restart interval. The default adaptive policy assesses at
accepted milestones and context-pressure signals; two compactions trigger an
assessment. The optional daily policy assesses once session age reaches 24 hours,
but still restarts only when the bounded forecast, remaining work and transfer
safety justify it.

When the client supports titles, each conversation keeps the stable task name and
adds its own start date: `<task title> | started DD-MM`. Flow removes an older
start suffix before applying the new one, stores the full timestamp and timezone
in the session registry, and reads the title back. Clients without title mutation
continue with the same safe handoff and report that cosmetic capability as
unsupported. Session IDs, goal identity and checkpoint digest remain authoritative.

The core is the [Sessions protocol](../skills/nobrainer-sessions/references/session-restart.md),
usable as instructions in any capable client. An optional deterministic helper
can be invoked by hooks. There is no universal hook event or universal archive
API: adapters must verify capabilities and map their actual lifecycle events.
A client without safe native transport prepares a manual continuation packet.

The helper calculates a conservative raw token proxy over at most three future
calls. Its defaults are heuristics, not an optimum or a billing forecast. Current
input, fresh startup and restart overhead can be observations or explicitly
labelled estimates. Missing metrics remain unknown. Large fixed instructions,
cache reuse and necessary re-reads may make restarting more expensive.

Quality is protected by checking the handoff before transfer, not by assuming
fresh sessions are smarter. Do not restart if acceptance, decisions or required
evidence cannot be reconstructed reliably. Do not archive the old session after
mere creation or a read-only ACK. Verify takeover first; archive failure never
returns implementation ownership to the old session.

## Proof and remaining limits

The shipped helper is tested with real CLI invocations and deterministic failure
cases. It only chooses actions from supplied observations. It does not collect
usage, authenticate an ACK, implement a lock, run a model, create sessions or
archive them. Native transport requires separate adapter runtime evidence.
No all-client automation, token-saving percentage or quality improvement has
been measured for this feature.

No new permanent module, scheduler, background service or global hook is added.
Existing `nobrainer-sessions`, `session-handoff` and manual recovery stay available.
Disable further rotation with policy `off`; a committed transfer never permits
both old and new sessions to resume writing.
