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

The GitHub source channel is `DISTRIBUTED` for `v1.5.0`, the latest published
source release. Its exact merge, tag, deterministic checks, secret scan and
isolated installer readback are recorded in the [publication evidence](releases/v1.5.0-publication-readback.md).
The current `main` documentation was aligned after tag creation through the
post-release metadata PR recorded there; the tag remains pinned to its reviewed
merge commit. `v1.4.0` remains the previous rollback source release, while
`v1.3.1`, `v1.3.0` and `v1.2.1` remain older accepted rollback releases. GitHub's
release API did not expose an immutability field in this readback and tag
protection was not independently verified, so security-sensitive consumers
should pin the reviewed full commit SHA. Source distribution does not prove
that a client marketplace accepted, loaded or ran the package; the per-client
rows remain `NOT_PUBLISHED` until that exact channel has an installation readback.

The published `v1.3.1` source adds the `BRIEF` writing contract and
surface-specific bug evidence. The source release is distributed and repository
checked; client-specific runtime and marketplace levels remain separately
evidence-scoped.

The pre-publication `v1.5.0` candidate checkpoint remains available in
[`docs/releases/v1.5.0.md`](releases/v1.5.0.md). The published source release
and its distribution proof are in the [v1.5.0 publication readback](releases/v1.5.0-publication-readback.md);
neither record upgrades the client rows below without client-specific evidence.

## Model-neutral readiness

`WORKFLOW_READY` is a product-positioning label, not a seventh compatibility
level. It means the portable policy can carry a selected model, effort, budget
and escalation gate; it does not prove that a provider exposes or follows that
policy.

| Model family | Workflow posture | Direct runtime proof in this repository |
|---|---|---|
| Astra | `WORKFLOW_READY`: model-neutral scope, budget and escalation contract | `NOT_VERIFIED`: OpenAI describes Astra as being prepared for release, and its current public API catalog does not list it |
| Claude Fable 5.1 / Mythos 5.1 | `WORKFLOW_READY`: portable skills with explicit effort and escalation boundaries | `NOT_VERIFIED`: no clean-session transcript for either release |
| Current Codex model catalog | `WORKFLOW_READY`: host-selected or explicitly routed model policy | `NOT_VERIFIED` per model variant; the client rows below remain the runtime source of truth |

The official Anthropic announcement uses the names Fable 5.1 and Mythos 5.1;
`Claude 5.1` is a convenient family description, not the exact model name.
See [OpenAI's Astra update](https://openai.com/index/path-to-astra/),
[OpenAI's model catalog](https://developers.openai.com/api/docs/models) and
[Anthropic's Fable 5.1/Mythos 5.1 announcement](https://www.anthropic.com/claude-fable-and-mythos-5-1).

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

The table describes the current repository source release, not private installations
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

For a long-running probe, read back `SESSION_HEALTH_GATE` at `START`,
`AFTER_COMPACTION`, `MATERIAL_TRANSITION` and `BEFORE_CLOSEOUT`, using the
host/configured policy rather than assuming universal limits. Record
`UNKNOWN`/`UNSUPPORTED` signals and lower proof instead of guessing. Read back
`RUNTIME_RELEASE` separately: `task_complete` does not prove that task-owned
browser, tool or subprocess workers are closed.
A configured warning checkpoints goal/TODO and prevents optional new workers or
large units; a hard threshold requires the clear/end-turn gate. Repository
examples are not universal host limits.
For resumable probes, persist one task-local Markdown `GOAL_FILE`. Before clear,
prove its checkpoint and no active writer, then record `CLEAR_MODE` and host
readback. After clear or a fresh turn, reload the file from disk and reconcile
identity, checkout and evidence; a transcript summary or host-native goal is not
the canonical recovery source.

### Automatic routing

The portable `ROUTED` policy describes how a plan may select an advertised
capability tier; it is not a cross-provider gateway. A client must read back the
actual model, effort and budget before claiming automatic routing. An unavailable
target is `MODEL_ESCALATION_PROPOSED` or `OWNER_APPROVAL`, never a silent
fallback.

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
SESSION_HEALTH_GATE:
RUNTIME_RELEASE:
OWNED_WORKER_READBACK:
EVIDENCE_PATH:
```

Marketplace screenshots, manifest parsing, an installer exit code, or a skill
appearing on disk do not replace this acceptance test.

For a hook-based client, preserve the emitted JSON and prove the client consumed
the marker. For OpenCode or Pi, preserve both adapter logs/readback and the first
model action. A prompt that pastes the skill body does not prove discovery. A
valid explicit `$nobrainer-ultra` run proves explicit loading, not automatic routing.
