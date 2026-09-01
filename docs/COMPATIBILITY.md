# Compatibility evidence

NoBrainer Tech Skills keeps one portable `skills/` source, but portability is
not the same as a proven client integration. Record these levels separately:

1. `SOURCE_VALIDATED` — the portable `SKILL.md` folders pass repository
   validators; this makes no client claim.
2. `REPOSITORY_CHECKED` — the manifest, hook, plugin or installer has a
   deterministic local parse or execution test against the repository's frozen
   contract; this does not prove the client accepts it.
3. `CLIENT_LOADED` — the exact installed client version accepts the package and
   reports the expected skills or bootstrap as loaded.
4. `RUNTIME_VERIFIED_EXPLICIT` — a clean client session loads and follows the
   canonical body under explicit invocation; this does not prove discovery.
5. `RUNTIME_VERIFIED` — a clean client session discovers and follows
   `nobrainer-ultra` without manually pasting its body.
6. `DISTRIBUTED` — the exact release is available through the claimed public
   marketplace or install channel and was read back after installation.

Never promote one level from evidence belonging to another.
Merge is a repository delivery state, not a client-compatibility level; release
evidence records it separately.

The GitHub source channel is `DISTRIBUTED` for `v1.3.0`, the latest fully
accepted source release. Its exact merge, tag, deterministic checks, secret scan
and calibrated final5 holdout are recorded in [the release evidence](releases/v1.3.0-publication-readback.md)
and [the behavioral receipt](evals/artifacts/v1.3.0-autoimprove-integrity-final5-receipt.md).
`v1.2.1` remains the rollback source release; `v1.2.0` remains available but
failed one archive-native test and is superseded. GitHub reports the `v1.3.0`
release object as non-immutable and tag protection was not independently
verified, so security-sensitive consumers should pin the reviewed full commit
SHA. Source distribution does not prove that a client marketplace accepted,
loaded or ran the package; the per-client rows remain `NOT_PUBLISHED` until
that exact channel has an installation readback. The rollback release evidence
also records an isolated installer readback.

`v1.0.0` remains a separately verified nine-skill rollback anchor with its own
[publication readback](releases/v1.0.0.md).

The v1.3.0 source release has additional local runtime evidence in
[the historical harness evaluation](evals/v1.3.0-harness-clarity-2026-08-30.md)
and current behavioral evidence in
[the Autoimprove evaluation](evals/v1.3.0-autoimprove-integrity-2026-09-01.md).
The older client transcripts remain hash-scoped and do not silently upgrade to
marketplace or automatic-routing claims. Both clients retain explicit-runtime
evidence only; automatic routing and client publication remain unverified.

## Current evidence

`REPOSITORY_CHECKED` below means deterministic repository tests passed. It does
not mean the external client's parser accepted or loaded the package.

| Client / harness | Source | Repository contract | Client load | Runtime | Distribution |
|---|---|---|---|---|---|
| Claude Code | `SOURCE_VALIDATED` | `REPOSITORY_CHECKED`: manifest, portable installer and Claude SessionStart output | `CLIENT_LOADED`: CLI `2.1.241`, isolated plugin, namespaced explicit invocation | `RUNTIME_VERIFIED_EXPLICIT`: final Ultra routed to and read canonical Autoimprove; automatic routing remains unverified | `NOT_PUBLISHED` |
| Codex | `SOURCE_VALIDATED` | `REPOSITORY_CHECKED`: accepted manifest schema and portable installer | `CLIENT_LOADED`: CLI `0.149.1`, repo-scoped copy, explicit canonical invocation | `RUNTIME_VERIFIED_EXPLICIT`: final Luna cases and isolated implementation passed; automatic and alias-only routing remain unverified | `NOT_PUBLISHED` |
| Cursor | `SOURCE_VALIDATED` | `REPOSITORY_CHECKED`: manifest path and Cursor SessionStart output | `NOT_VERIFIED` | `NOT_VERIFIED` | `NOT_PUBLISHED` |
| OpenCode | `SOURCE_VALIDATED` | `REPOSITORY_CHECKED`: skills registration plus idempotent first-user transform | `NOT_VERIFIED` | `NOT_VERIFIED` | `NOT_PUBLISHED` |
| GitHub Copilot CLI | `SOURCE_VALIDATED` | `REPOSITORY_CHECKED`: portable installer and repository instructions; no bootstrap | `NOT_VERIFIED` | `NOT_VERIFIED` | `NOT_PUBLISHED` |
| Gemini CLI | `SOURCE_VALIDATED` | `REPOSITORY_CHECKED`: extension manifest and owned context include | `NOT_VERIFIED` | `NOT_VERIFIED` | `NOT_PUBLISHED` |
| Kimi Code | `SOURCE_VALIDATED` | `REPOSITORY_CHECKED`: canonical skills path, Ultra session-start field and native-tool boundary | `NOT_VERIFIED` | `NOT_VERIFIED` | `NOT_PUBLISHED` |
| Devin CLI | `SOURCE_VALIDATED` | no dedicated adapter | `NOT_VERIFIED` | `NOT_VERIFIED` | `NOT_PUBLISHED` |
| Pi | `SOURCE_VALIDATED` | `REPOSITORY_CHECKED`: package resources, dedupe, lifecycle reset and post-compaction transform | `NOT_VERIFIED` | `NOT_VERIFIED` | `NOT_PUBLISHED` |
| Hermes Agent | `SOURCE_VALIDATED` | `REPOSITORY_CHECKED`: root Agent Plugins v1 manifest only; no bootstrap | `NOT_VERIFIED` | `NOT_VERIFIED` | `NOT_PUBLISHED` |
| Antigravity and other plugin hosts | `SOURCE_VALIDATED` | no host-specific contract | `NOT_VERIFIED` | `NOT_VERIFIED` | `NOT_PUBLISHED` |
| Generic Agent Skills consumers | `SOURCE_VALIDATED` | canonical folders only | `NOT_VERIFIED` | `NOT_VERIFIED` | `NOT_PUBLISHED` |

The table describes the current repository candidate, not private installations
on a maintainer's machine. There is deliberately no blanket “works everywhere”
badge: an unknown harness gets portable skill folders, then needs its own
discovery/bootstrap proof before promotion.

## Adapter contract

All adapters point at the same fifteen directories. They may expose discovery and
one small `NOBRAINER_BOOTSTRAP_V1` routing context, but they must not copy or
rewrite skill bodies.

- Claude and Cursor hooks emit exactly one platform-specific JSON field.
- OpenCode and Pi inject once per relevant context and detect their marker;
  Pi permits one re-injection after compaction.
- Gemini includes an extension-owned context file instead of changing a user's
  global instructions.
- Kimi maps native tools but explicitly refuses to treat a hidden subagent as
  proof of visible cross-session transport.
- Codex uses native skill discovery and has no hook entry or default
  `hooks/hooks.json` file. Claude points explicitly to
  `hooks/claude-hooks.json`, preventing Codex from auto-discovering the
  Claude-specific SessionStart adapter.
- The portable root manifest contains no client-specific bootstrap. Hermes can
  consume it through its Agent Plugins path, where skills remain namespaced and
  explicitly selected until a clean runtime transcript proves more.
- Copilot and Devin use portable skill folders and repository instructions only;
  no dedicated startup hook or client plugin contract is claimed.

## Clean-session acceptance

For each client, record the exact client version, model, operating system,
installation source and commit or release. Start with no project-specific rule
that names NoBrainer. Preserve the complete transcript and use these probes:

### Automatic routing

```text
Help me design and implement an ambiguous feature that crosses several modules
and may affect production.
```

Passing behavior:

- `nobrainer-ultra` is selected without pasting its body;
- the agent enters a short requirements/acceptance gate before writes;
- it creates one canonical plan and shows a compact Progress checklist;
- production effects remain owner-gated;
- it does not manufacture workers before work units exist.

### Correction and review loop

```text
I changed my mind: keep the public API unchanged. Update the plan accordingly.
```

Passing behavior: the old requirement is marked superseded, dependent TODO
items and evidence are invalidated, and the affected route is rebuilt without a
second ordinary clarification round. A simulated verified review finding must
return to Build and then fresh Review; it may not reuse the old green result.

### Explicit canonical invocation

```text
$nobrainer-ultra Deliver this task with the smallest safe workflow.
```

Passing behavior: the client loads the canonical `nobrainer-ultra` body and any
required relative reference without the user pasting either one.

### Implicit alias control

```text
Use nb-ultra to deliver this task with the smallest safe workflow.
```

`nb-ultra` is a trigger phrase in the description, not a second skill name.
Record whether the client supports and selects it through implicit matching.
Do not present this as an explicit invocation guarantee. In the v1.3.0 Codex
probe, alias-only selection failed under a crowded skill catalog and a prompt
that prohibited file reads; the canonical `$nobrainer-ultra` probe passed.

### Non-trigger control

```text
Fix this obvious typo in README.md.
```

Passing behavior: one primary session makes the bounded correction without SDD,
a wiki, or a worker swarm.

## Runtime evidence record

Store a transcript or durable report with:

```text
CLIENT:
CLIENT_VERSION:
MODEL:
OS:
INSTALL_SOURCE:
RELEASE_OR_COMMIT:
SKILL_SHA256:
INVOCATION: CANONICAL_EXPLICIT | IMPLICIT_DESCRIPTION
PROMPT:
SKILL_DISCOVERED:
FIRST_WRITE_BEFORE_GATE: YES | NO
RESULT: PASS | FAIL | BLOCKED
EVIDENCE_PATH:
```

Marketplace screenshots, manifest parsing, an installer exit code, or a skill
appearing on disk do not replace this acceptance test.

For a hook-based client, preserve the emitted JSON and prove the client consumed
the marker. For OpenCode or Pi, preserve both adapter logs/readback and the first
model action. A prompt that pastes the skill body does not prove discovery. A
valid explicit `$nobrainer-ultra` run proves explicit loading, not automatic routing.
