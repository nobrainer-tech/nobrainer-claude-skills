# NoBrainer Tech Skills release notes

## v1.3.0 candidate — 2026-08-30

This untagged candidate keeps exactly fifteen portable skills:

- `nobrainer-ultra`
- `nobrainer-team`
- `nobrainer-dispatcher`
- `nobrainer-research`
- `nobrainer-writing`
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

- Ultra uses a short natural-language scope and Progress checklist for ordinary
  work; a durable ledger appears only for dependencies, handoff, recovery,
  multiple writers or consequential external effects.
- The scope guard now names expected files, proof, untouched work, the minimum
  solution and clean completion before a non-trivial write.
- Stable local errors start from local evidence. Current, uncertain or
  high-stakes remedies still route to bounded primary-source research.
- Codex installation follows the shared `.agents/skills` convention and
  documents `$nobrainer-ultra` as the canonical explicit invocation. The short
  alias remains an implicit-routing hint, not a second skill name.
- Public automation may fetch remote refs but cannot commit, push, open a PR or
  merge. Versioned guards reject backup paths and automated commit identities.
- Root instructions and Ultra are smaller while preserving owner gates,
  correction, recovery, review and receive-audit boundaries.

The source-isolated Codex candidate passed the development, local-error and two
holdout probes. Alias-only discovery failed and Claude runtime remains blocked
by an expired local OAuth session, so this is not a merged, tagged, distributed
or cross-client accepted release. Exact evidence and limits are recorded in
[the v1.3.0 candidate checkpoint](docs/releases/v1.3.0.md).

## v1.2.1 — 2026-08-28

This patch release contains exactly fifteen portable skills:

- `nobrainer-ultra`
- `nobrainer-team`
- `nobrainer-dispatcher`
- `nobrainer-research`
- `nobrainer-writing`
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

The patch makes the frozen-payload attributes test portable. It now verifies
real `git check-attr` behavior in an isolated temporary repository, so a source
archive without the repository's `.git` directory receives the same strict
check instead of failing before validation.

This version is published as a tagged GitHub source release at commit
`373dced811e277615d9d0301c88fd9781741d6bc`. Tag identity, CI, downloaded
archive parity and checksum, 88/88 archive-native tests, secret scan and an
isolated fifteen-skill copy-install readback are recorded in
[the v1.2.1 evidence](docs/releases/v1.2.1.md). This is not a claim of client
marketplace publication, native loading or clean-session runtime behavior.

## v1.2.0 — 2026-08-28

The release contains exactly fifteen portable skills:

- `nobrainer-ultra`
- `nobrainer-team`
- `nobrainer-dispatcher`
- `nobrainer-research`
- `nobrainer-writing`
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

- Dispatcher owns dependency readiness, bounded batch selection, backpressure
  and audited result routing without duplicating Team or Sessions.
- Ultra routes multiple delegated work units through Team, Dispatcher and
  Sessions, while one coherent task stays in MAIN.
- Raw worker reports and `NEXT_ACTION` never release dependent work before an
  independent receive-audit.
- Writing compresses messages, comments and documents without dropping facts,
  caveats, voice or action, and retires detector-oriented humanizer behavior.
- The problem gate checks targeted wiki context and current internet evidence
  before choosing a remedy for an error, ambiguity or complication.
- Installer mappings retire generic dispatcher aliases into one canonical
  skill, and all adapters share the same fifteen-skill source tree.
- Copy installs are verified in private staging and published with atomic
  no-replace semantics, so a concurrent foreign target is preserved.

This version was published as a tagged GitHub source release at commit
`afd0bffa3f287493a4f646b9ceaafb82273e46b0`. Its repository CI, source parity,
secret scan, skill validation and isolated installer readback passed, but the
downloaded archive exposed one environment-dependent test that assumed the
presence of `.git`. It is therefore published but not fully accepted and is
superseded by the accepted `v1.2.1` release. The complete boundary is recorded
in [the v1.2.0 evidence](docs/releases/v1.2.0.md).

## v1.1.0 — 2026-08-28

The release contains exactly thirteen portable skills:

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

This version is published as a tagged GitHub source release at commit
`d6931a1006bf0180955d8437fd93174b6a512428`. Tag identity, archive SHA-256, file
parity, CI, tests, secret scan and isolated installer readback are recorded in
[the v1.1.0 evidence](docs/releases/v1.1.0.md). This is not a claim of
publication in npm or any client marketplace, nor of native client loading or
runtime behavior.

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
