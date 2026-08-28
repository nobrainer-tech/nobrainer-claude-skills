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
4. `RUNTIME_VERIFIED` — a clean client session discovers and follows
   `nobrainer-ultra` without manually pasting its body.
5. `DISTRIBUTED` — the exact release is available through the claimed public
   marketplace or install channel and was read back after installation.

Never promote one level from evidence belonging to another.

The GitHub source channel is `DISTRIBUTED` for `v1.1.0`: release, tag-to-commit,
CI, downloaded-archive file parity, secret scan and isolated installer readback
of all thirteen skills are recorded in
[the release evidence](releases/v1.1.0.md). GitHub reports this release as
mutable, so security-sensitive consumers should pin the full commit SHA. This
does not prove that a client marketplace accepted, loaded or ran the package;
the per-client rows remain `NOT_PUBLISHED` until that exact channel has an
installation readback.

`v1.0.0` remains a separately verified nine-skill rollback anchor with its own
[publication readback](releases/v1.0.0.md).

## Current evidence

`REPOSITORY_CHECKED` below means deterministic repository tests passed. It does
not mean the external client's parser accepted or loaded the package.

| Client / harness | Source | Repository contract | Client load | Runtime | Distribution |
|---|---|---|---|---|---|
| Claude Code | `SOURCE_VALIDATED` | `REPOSITORY_CHECKED`: manifest, portable installer and Claude SessionStart output | `NOT_VERIFIED` | `NOT_VERIFIED` | `NOT_PUBLISHED` |
| Codex | `SOURCE_VALIDATED` | `REPOSITORY_CHECKED`: manifest, empty hook isolation and portable installer | `NOT_VERIFIED` | `NOT_VERIFIED` for this public package | `NOT_PUBLISHED` |
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

The table describes this repository candidate, not private installations on a
maintainer's machine. There is deliberately no blanket “works everywhere”
badge: an unknown harness gets portable skill folders, then needs its own
discovery/bootstrap proof before promotion.

## Adapter contract

All adapters point at the same thirteen directories. They may expose discovery and
one small `NOBRAINER_BOOTSTRAP_V1` routing context, but they must not copy or
rewrite skill bodies.

- Claude and Cursor hooks emit exactly one platform-specific JSON field.
- OpenCode and Pi inject once per relevant context and detect their marker;
  Pi permits one re-injection after compaction.
- Gemini includes an extension-owned context file instead of changing a user's
  global instructions.
- Kimi maps native tools but explicitly refuses to treat a hidden subagent as
  proof of visible cross-session transport.
- Codex declares an empty hook map so it does not accidentally consume Claude
  hook shapes; native skill discovery remains the routing mechanism.
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
- it creates a complete execution map with one owning method per stage;
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

### Explicit alias

```text
Use nb-ultra to deliver this task with the smallest safe workflow.
```

Passing behavior: the client resolves the alias from the skill description and
loads the canonical `nobrainer-ultra` body.

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
PROMPT:
SKILL_DISCOVERED:
FIRST_WRITE_BEFORE_GATE: YES | NO
RESULT: PASS | FAIL | BLOCKED
EVIDENCE_PATH:
```

Marketplace screenshots, manifest parsing, an installer exit code, or a skill
appearing on disk do not replace this acceptance test.

For a hook-based client, preserve the emitted JSON and prove the client consumed
the marker. For OpenCode or Pi, preserve both adapter logs/readback and
the first model action. A manual prompt that pastes `nobrainer-ultra` does not
prove automatic routing.
