# Adaptive session restart review — 2026-09-05

Owner outcome: long tasks maintain progress in files and choose fresh sessions
quietly when worthwhile, without binding the workflow to a model or client.

## Baseline gap and minimal decision

The existing Sessions protocol unconditionally prohibited automatic successors,
even after standing owner consent, and had no executable restart decision gate.
It already owned identity, handoff, health and recovery. Extend that module;
retain fifteen modules and all existing installation identities.

The baseline gap is a source-contract observation, not a model-behavior failure
trial. The candidate adds an optional stdlib decision helper, compact handoff
protocol and route alias. It creates no background service, scheduler or global
hook, and does not pretend to implement client session APIs.

## Primary-source context

- [OpenAI compaction](https://developers.openai.com/api/docs/guides/compaction):
  compaction carries prior state using fewer tokens; it does not establish that
  starting a new conversation is always cheaper or more accurate.
- [OpenAI agent loop](https://openai.com/index/unrolling-the-codex-agent-loop/):
  client context and compaction are host implementation concerns.
- [Claude Code hooks](https://code.claude.com/docs/en/hooks-guide): lifecycle
  events and hook output have client-specific contracts. Portable protocol and
  per-client transport are separate requirements.

These are host documentation inspirations, not new workflow competitors; no
new competitor comparison page is appropriate.

## Safety review and pressure cases

An independent design review required preserving worker successor prohibitions,
standing consent, uncertain-create reconciliation, stale-ACK rejection, released
writers, conditional ownership transfer and archive-after-takeover. The shipped
helper tests exercise those decisions directly rather than copying its logic.
A real competing ownership transition requires adapter-level testing; the helper
neither acquires locks nor makes that transition.

The adaptive forecast covers at most three upcoming calls and includes startup
and transfer overhead. Age and compaction count trigger assessment, not restart.
Unknown economics does not fabricate a saving. Repeated automatic restart
without useful progress is refused. The raw token proxy is explicitly distinct
from cached-input pricing, account limits and measured model quality.

## Verification and scope

152 deterministic tests passed, including twelve tests of the shipped restart
helper, CLI malformed/oversized input and failure paths. Canonical suite
validation passed. Bootstrap remains within 190 words and Ultra within 1600;
long detail is loaded only through Sessions/long-run references.

No live conversation was created or archived for this test. End-to-end native
restart and net token/quality gains remain unverified per client. This is a
development feature after v1.7.1, not a retroactive change to its archive.

README, compatibility/testing docs, Sessions protocol, long-run recovery,
bootstrap and alias tests are reconciled. Existing workflow diagram needs no
new node: Sessions still owns health, handoff and recovery; new mode detail
belongs in the linked guide (diagram change NOT_NEEDED).
