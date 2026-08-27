# Baseline captured output

Outcome: minimal setup is appropriate, but this read-only test stops before
execution. No files changed and nothing installed.

- Preserve the existing `AGENTS.md` and any `CLAUDE.md` or managed blocks.
- Add only a short marked `NB-ULTRA` block if equivalent workflow guidance is
  genuinely missing; link canonical guidance instead of copying protocols.
- Keep one `<repo> | MAIN` session. Add workers only for bounded independent
  work.
- Do not create a wiki, SDD, auto-improvement loop, or extra project artifacts
  without a concrete need.
- Detect Superpowers separately in the Codex and Claude Code harnesses. Require
  the official namespaced/plugin source, verify capability readback, and never
  vendor or copy its skills into the repository.
- If an official required capability is missing, stop with one installation or
  repair action for owner approval.

Lifecycle state: design-level drift is `RECONCILABLE`; `READY_GATE` is not
passed because actual repository state and runtime capabilities were
intentionally not inspected, and edits/installations are prohibited in this
test.

Acceptance for a later authorized setup: existing rules remain intact, the
minimal NoBrainer lifecycle is discoverable, official Superpowers capabilities
resolve unambiguously in both clients, and readback proves the configuration.

Evidence evaluated: commit `f8d4f0b05359b5765e8c826b9ca5fd433aa3ebf8`,
limited to `HEAD:skills/nobrainer-ultra/SKILL.md` and its explicit
`HEAD:skills/nobrainer-ultra/references/routing.md` reference.

Next action: authorize a read/write setup pass that first performs the
repository and capability drift check, then presents or applies only the
missing minimal changes.

Rollback: none required; this test made zero mutations.
