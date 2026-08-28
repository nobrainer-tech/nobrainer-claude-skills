# NoBrainer Tech Skills release notes

## v1.0.0 — 2026-08-28

The first stable source release contains exactly nine portable, lightweight
skills:

- `nobrainer-ultra`
- `nobrainer-sessions`
- `nobrainer-spec-driven-development`
- `nobrainer-wiki`
- `nobrainer-browser`
- `nobrainer-autoimprove`
- `nobrainer-decide`
- `nobrainer-rca`
- `nobrainer-review`

The same canonical skill tree is packaged with thin repository-checked adapters
for Claude Code, Codex, Cursor, OpenCode, Gemini CLI, Kimi Code, Pi and generic
Agent Plugins consumers. Official Superpowers remains an external dependency;
its skills are not copied into this package.

Distribution target: a tagged GitHub source release. At the release-preparation
stage this file does not claim publication; that is proven only after GitHub
release and tag-to-commit readback. This is not a claim of publication in npm or
any client marketplace, and adapter checks are not clean-session runtime proof.
Current evidence and limits are recorded in
[the compatibility matrix](docs/COMPATIBILITY.md) and
[the testing guide](docs/TESTING.md).

After publication, install from the tag:

```bash
git clone --branch v1.0.0 --depth 1 https://github.com/nobrainer-tech/nobrainer-tech-skills.git
cd nobrainer-tech-skills
python3 scripts/validate_skills.py --suite
python3 scripts/install_skills.py --client codex
```

Review the dry-run before adding `--apply`. To roll back a local install, remove
only links created from this checkout or restore the exact previously reviewed
Git ref recorded by the project; do not delete a shared skills directory.
