# NoBrainer Tech Skills release notes

## v1.1.0 — 2026-08-28 (release candidate)

The candidate contains exactly thirteen portable skills:

- `nobrainer-ultra`
- `nobrainer-team`
- `nobrainer-research`
- `nobrainer-build`
- `nobrainer-security`
- `nobrainer-sessions`
- `nobrainer-spec-driven-development`
- `nobrainer-wiki`
- `nobrainer-browser`
- `nobrainer-autoimprove`
- `nobrainer-decide`
- `nobrainer-rca`
- `nobrainer-review`

Highlights:

- Ultra now creates a complete skill-routed execution map after one focused
  requirements round, then continues through routine approved work.
- Team separates capability/role design from Sessions transport and can inspect
  local skills or safely evaluate one temporary external specialist.
- Research, Build and Security own current evidence, implementation quality and
  trust-boundary risk instead of leaving those concerns implicit.
- Correction hooks update superseded decisions, project lessons and durable
  wiki knowledge without duplicating mutable truth or secrets.
- Failed Review routes back to Build and requires fresh verification/review.
- The workflow graphic, adapters, installer, aliases and behavior tests are
  aligned with the thirteen-skill inventory.
- Installer migration and failed-copy rollback never delete a quarantined
  pathname after fingerprinting; exact recovery claims are preserved and
  reported for post-readback manual cleanup.

This section is a release-candidate contract, not a publication claim. Exact
tag, commit, archive checksum, CI and isolated installer readback will be added
after the reviewed PR is merged and the GitHub release exists.

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
Agent Plugins consumers. External capability portfolios are not copied into this
package.

This version is published as a tagged GitHub source release. Exact release,
tag-to-commit, CI and downloaded-archive readback are recorded in
[the v1.0.0 evidence](docs/releases/v1.0.0.md). This is not a claim of publication
in npm or any client marketplace, and adapter checks are not clean-session
runtime proof. Current evidence and limits are recorded in
[the compatibility matrix](docs/COMPATIBILITY.md) and
[the testing guide](docs/TESTING.md).

Install the exact reviewed commit behind `v1.0.0`:

```bash
git clone https://github.com/nobrainer-tech/nobrainer-tech-skills.git
cd nobrainer-tech-skills
git checkout --detach bf60c4c3a57440c6b87cd1b326cd41237b7225da
test "$(git rev-parse HEAD)" = "bf60c4c3a57440c6b87cd1b326cd41237b7225da"
python3 scripts/validate_skills.py --suite
python3 scripts/install_skills.py --client codex
```

Review the dry-run before adding `--apply`. To roll back a local install, remove
only links created from this checkout or restore the exact previously reviewed
Git ref recorded by the project; do not delete a shared skills directory.
