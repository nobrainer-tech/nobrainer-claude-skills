# Candidate captured output

## Setup

No setup was performed. This read-only preflight changed no files,
configuration, skills, or plugins.

```text
EXECUTION_MODE: COPILOT
MODE: SETUP
LIFECYCLE: DRIFT_CHECK=OWNER_DECISION; BUDDY=COMPLETE; READY_GATE=NOT_READY
AUTOPILOT: NOT_RUN
VERIFY: NOT_RUN
RECEIVE_AUDIT: NOT_RUN

NOBRAINER_SOURCE: Supplied portable checkout; canonical durable source still to confirm
CLIENTS_CONFIGURED: NONE
SUPERPOWERS_SOURCE: https://github.com/obra/superpowers
SUPERPOWERS_VERSION: Upstream v6.3.0; installed versions unknown
PROJECT_INSTRUCTIONS: Existing AGENTS.md preserved; target contents not inspected
SDD: NOT_NEEDED
WIKI: NOT_NEEDED
SESSIONS: NOT_NEEDED
```

Smallest write-enabled reconciliation:

1. Inspect the named target repository, dirty state, existing `AGENTS.md` and
   `CLAUDE.md`, client versions, discovered skills and plugin collisions.
2. Install only `nobrainer-ultra` initially from one canonical NoBrainer source.
   Dry-run `scripts/install_skills.py` separately for `--client codex` and
   `--client claude`, review every target, then use `--apply` only if
   conflict-free.
3. Preserve `AGENTS.md`. Add one short `NOBRAINER-WORKFLOW` block using the
   canonical START/END markers only if equivalent workflow and owner gates are
   missing.
4. If absent, create a minimal `CLAUDE.md` containing `@AGENTS.md`; Claude Code
   officially recommends this rather than duplicating existing rules.
   [Claude Code project-instruction documentation](https://code.claude.com/docs/en/memory)
5. Install Superpowers separately through each native marketplace:
   - Claude Code: `/plugin install superpowers@claude-plugins-official`
   - Codex App: Plugins, Coding, Superpowers, `+`
   - Codex CLI: `/plugins`, search `superpowers`, Install Plugin

   These are the current official channels; upstream's latest release is
   currently `v6.3.0`.
   [Official installation guidance](https://github.com/obra/superpowers#installation),
   [v6.3.0 release](https://github.com/obra/superpowers/releases/tag/v6.3.0)
6. Do not create SDD, wiki, task registry, sessions, workers, or copied
   Superpowers skills. Add optional NoBrainer capabilities only when an actual
   task justifies them.

## Attention and risk

```text
MAX_ACTIVE_WORK: 1
NOTIFICATION_SEVERITY: URGENT_BLOCKERS
DIGEST_CADENCE: One completion report
QUIET_PERIOD: Routine setup steps
EXPECTED_WAIT: One bounded setup pass plus two clean-session checks
MAX_CONTEXT_SWITCHES: 1
```

Stop for conflicting install targets, uncommitted overlap in instruction files,
login/trust prompts, ambiguous global-versus-project scope, or duplicate skill
triggers.

## Content quality

```text
PURPOSE_AUDIENCE: Owner deciding whether to authorize minimal setup
CORRECTNESS: Canonical NoBrainer references, official upstream channels, runtime readback
COMPLETENESS: Codex, Claude Code, instructions, discovery, rollback
COHERENCE: One NoBrainer source; no duplicated protocols
FEEDBACK_OR_REVIEW: Owner reviews dry-run and instruction diff
QUALITY_STATUS: ASSESSED
```

## Verification

```text
STATIC_CHECKS: Skill, routed setup/compatibility references, installer behavior, and official Superpowers channels reviewed
RUNTIME_CHECKS: NOT_RUN
UNVERIFIED: Target state, client versions, installed plugins, resolved versions, trigger collisions, clean-session routing
```

After installation, both clients must list the expected skills and pass
fresh-session probes for automatic `nobrainer-ultra` routing, explicit
`nb-ultra`, owner gates, and a trivial-task control that creates no SDD, wiki,
or workers. Repository tests and eval documents were intentionally not
inspected.

## Recovery

```text
RECOVERY_STATE: OWNER_DECISION_REQUIRED
RETRY_BUDGET: One retry per client after new evidence
ROLLBACK_NOW: None required; nothing changed
ROLLBACK_AFTER_SETUP: Restore instruction preimages, remove only NoBrainer targets created by this run, uninstall Superpowers through each native plugin manager, restart both clients, and confirm readback
```

## Open assumptions

The target repository path, canonical durable NoBrainer checkout, and
installation scope remain unspecified.

`OWNER_ACTION_REQUIRED:` authorize one write-enabled reconciliation against the
named repository and its Codex and Claude Code profiles.
