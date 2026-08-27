# Compatibility evidence

NoBrainer Tech Skills keeps one portable `skills/` source, but portability is
not the same as a proven client integration. Record these levels separately:

1. `SOURCE_VALIDATED` — the client can consume portable `SKILL.md` folders and
   the repository validators pass.
2. `ADAPTER_VALIDATED` — the client manifest, hook, plugin, or installer path
   has a deterministic local readback.
3. `RUNTIME_VERIFIED` — a clean client session discovers and follows
   `nobrainer-ultra` without manually pasting its body.
4. `DISTRIBUTED` — the exact release is available through the claimed public
   marketplace or install channel and was read back after installation.

Never promote one level from evidence belonging to another.

## Current evidence

| Client | Source | Adapter | Runtime | Distribution |
|---|---|---|---|---|
| Claude Code | `SOURCE_VALIDATED` | local manifest/install test | `NOT_VERIFIED` | `NOT_PUBLISHED` |
| Codex | `SOURCE_VALIDATED` | local manifest/install test | `NOT_VERIFIED` for this package | `NOT_PUBLISHED` |
| Cursor | `SOURCE_VALIDATED` | manifest configured and parsed | `NOT_VERIFIED` | `NOT_PUBLISHED` |
| OpenCode | `SOURCE_VALIDATED` | config hook import test | `NOT_VERIFIED` | `NOT_PUBLISHED` |
| GitHub Copilot | `SOURCE_VALIDATED` | local install + repo instructions | `NOT_VERIFIED` | `NOT_PUBLISHED` |

The table describes this repository release candidate, not every private skill
installation on the maintainer's machines.

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
- production effects remain owner-gated;
- it does not manufacture workers before work units exist.

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
