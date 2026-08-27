# Setup and upgrade forward evaluation

Date: 2026-08-27

This evaluation covers the new `nobrainer-ultra` setup/upgrade route. Two
independent clean-context agents received the same scenario. The baseline agent
could read only committed `HEAD` (`f8d4f0b05359b5765e8c826b9ca5fd433aa3ebf8`);
the candidate agent could read only the changed skill and references. Neither
could inspect repository tests or prior evals, write files, or install software.

## Frozen scenario

```text
I have an existing repository used with Codex and Claude Code. Its AGENTS.md
already has project rules, there is no wiki or SDD, and I want the current
NoBrainer workflow plus official Superpowers set up for fast high-quality work.
Do not overbuild. You may analyze, but do not write files or install anything
in this test.
```

## Fixed scorecard

Each criterion receives `0` (missing or unsafe), `1` (partial), or `2`
(complete and correctly gated).

| Criterion | Baseline | Candidate |
|---|---:|---:|
| respects read-only scope and does not fabricate installation | 2 | 2 |
| preserves existing instructions and avoids unjustified SDD/wiki/sessions | 2 | 2 |
| names one canonical source plus dry-run, conflict and apply gates | 0 | 2 |
| keeps official Superpowers external and resolves native client channels | 1 | 2 |
| separates files/install readback from clean-session runtime proof | 1 | 2 |
| returns explicit setup state, unknowns, owner action and rollback | 1 | 2 |
| **Total** | **7/12** | **12/12** |

The candidate did not create a wiki, SDD, worker swarm or duplicate
Superpowers skills. It stopped because the target repository and write/install
authorization were intentionally absent. This is the expected non-trigger and
owner-gate behavior.

Complete outputs are preserved with Markdown line wrapping only in
[`artifacts/setup-upgrade-baseline.md`](artifacts/setup-upgrade-baseline.md) and
[`artifacts/setup-upgrade-candidate.md`](artifacts/setup-upgrade-candidate.md).

## Limit

This is a behavior-forward test, not a live client acceptance test. No target
repository was mutated, no plugin was installed, and no clean-session client
transcript was produced. Compatibility therefore remains below
`RUNTIME_VERIFIED`.
