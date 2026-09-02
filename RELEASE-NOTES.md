# NoBrainer Tech Skills release notes

## v1.5.0 — 2026-09-02

This published source release keeps exactly fifteen portable skills and closes
the v1.4.0 public-surface coherence gap.

Highlights:

- `nobrainer-ultra` now freezes a portable `STANDARD`/`EXTENDED`/`ROUTED` model
  policy with explicit model, effort, budget and escalation fields; Dispatcher
  and Sessions carry the policy without silently switching models.
- The README presents v1.5.0 as an Astra Ready Flow for current Codex and
  Claude Fable 5.1 / Mythos 5.1 workflows, with direct runtime compatibility
  kept evidence-scoped.
- `nobrainer-ultra` now requires a `PUBLIC_SURFACE` decision for every change:
  update affected README, docs, templates, assets and flow, or record
  `NOT_NEEDED` with a reason. Public contract, routing and workflow changes use
  the full lifecycle and require fresh SVG and README Mermaid readback.
- `nobrainer-writing` now uses a compact `ENV:` block for bugs and comments;
  bug reports omit speculative workaround and root-cause fields, while feature
  issues keep a one-sentence Description, affected user, desired outcome and evidence.
- The quick path is limited to small reversible edits with no public contract,
  routing, workflow or portfolio impact.
- `CONTRIBUTING.md` and the pull-request template carry the same coherence
  checklist for human review.
- README's Mermaid flow and `assets/nobrainer-workflow.svg` now show the quick
  path and coherence gate.
- The v1.4.0 publication gap is recorded in
  [`docs/releases/v1.4.0-publication-readback.md`](docs/releases/v1.4.0-publication-readback.md).

Source publication is verified in the
[`v1.5.0 publication readback`](docs/releases/v1.5.0-publication-readback.md).
The pre-publication checkpoint remains in [`docs/releases/v1.5.0.md`](docs/releases/v1.5.0.md),
and direct provider runtime support remains separately evidence-scoped.

## v1.4.0 — 2026-09-02

This published source release keeps exactly fifteen portable skills:

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

- `nobrainer-ultra` now has an explicit quick path for one coherent,
  reversible small change, with a local check and diff/status readback before
  reporting; risk, scope or owner-gate expansion escalates to the full flow.
- `nobrainer-writing` uses one environment block for bugs and comments, containing
  the environment name, exact URL and user used; bug reports keep only an
  explicit `Description` and use `Evidence` for UI screenshots or MP4 recordings.
- API request/response and database query/result proof remain separate and
  copyable, while the public bug template follows the same contract.

The source release is merged in PR #35 at commit
`215c0bb0d6dbfe9b45ecf3202ec198a2c219b3b2`, tagged as `v1.4.0` and published on
GitHub. The archive and installation readback are recorded in
[`docs/releases/v1.4.0-publication-readback.md`](docs/releases/v1.4.0-publication-readback.md),
which also records the post-release coherence gap that v1.5.0 closes.

## v1.3.1 — 2026-09-02

This published source release keeps exactly fifteen portable skills:

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

- `nobrainer-writing` adds the English-first `BRIEF` mode and the `nb-brief`
  alias for short comments, bug reports, issues, user stories and requests.
- Bug reports keep `Environment`, `URL`, `Steps to reproduce`, `Current
  behavior`, `Expected behavior` and `Evidence` as separate fields.
- API evidence requires request and response, database evidence requires a
  read-only query and result, and UI evidence requires a screenshot or MP4.
  Missing required proof returns `INPUT_REQUIRED` instead of a weaker substitute.
- The repository's public bug template follows the same diagnostic contract;
  no sixteenth skill or client-specific fork was introduced.

The source release is merged in PR #33 at commit
`d1e0ea761d4bf439973727668ee871e2b367797e`, tagged as `v1.3.1` and published on
GitHub. The exact publication evidence is recorded in
[`docs/releases/v1.3.1-publication-readback.md`](docs/releases/v1.3.1-publication-readback.md);
the candidate checkpoint and BRIEF evaluation remain available in
[`docs/releases/v1.3.1.md`](docs/releases/v1.3.1.md) and
[`the BRIEF evaluation`](docs/evals/v1.3.1-writing-brief-2026-09-02.md).

## v1.3.0 — 2026-09-01

This published source release keeps exactly fifteen portable skills:

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
- Every current public head and release tag was checked for the exact retired
  backup identity and trailer. Affected refs were rewritten with exact leases
  while preserving every source tree; unrelated historical authors and
  committers were intentionally preserved. GitHub-managed historical
  pull-request refs remain outside repository write control.
- Root instructions and Ultra are smaller while preserving owner gates,
  correction, recovery, review and receive-audit boundaries.
- Autoimprove now separates candidate and evaluator ownership, calibrates the
  scoring path, binds per-trial receipts, handles noise and continues Pareto-
  sized fresh experiments after a rejected candidate. A bundled counter makes
  serialized-newline word limits reproducible.
- The final5 candidate passed three paired repetitions and a sealed holdout;
  the full evidence is in the [Autoimprove receipt](docs/evals/artifacts/v1.3.0-autoimprove-integrity-final5-receipt.md).

The source release is merged in PR #31 at commit
`8ae4a26548ce908fc5f98b22663f52e163541f56`, tagged as `v1.3.0` and published on
GitHub. Client compatibility remains separate: alias discovery and marketplace
distribution require their own clean-session readback. Exact release and
behavioral evidence are recorded in [the v1.3.0 post-release readback](docs/releases/v1.3.0-publication-readback.md).

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
`0010140d19a7ff847dff776569772ef04d82c314`. Current tag identity,
tree-equivalent historical CI, downloaded archive parity and checksum, 88/88
archive-native tests, secret scan and an
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
`46feb1e95567db6967ea718cb75051c507ada02f`. Its tree-equivalent historical CI,
source parity, secret scan, skill validation and isolated installer readback passed, but the
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
`711be31d654835a04ef8c70674c3e493aeb2da8a`. Current tag identity, archive
SHA-256, file parity, tree-equivalent historical CI, tests, secret scan and
isolated installer readback are recorded in
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
git checkout --detach 55c49f40d7dc4ebe900f139711cd46617c706233
test "$(git rev-parse HEAD)" = "55c49f40d7dc4ebe900f139711cd46617c706233"
python3 scripts/validate_skills.py --suite
python3 scripts/install_skills.py --client codex
```

Review the dry-run before adding `--apply`. To roll back a local install, remove
only links created from this checkout or restore the exact previously reviewed
Git ref recorded by the project; do not delete a shared skills directory.
