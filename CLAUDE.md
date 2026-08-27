# Working in nobrainer-tech-skills

This public repository is the canonical, client-neutral source for NoBrainer
Agent Skills. Claude Code, Codex, Cursor, OpenCode and GitHub Copilot use the
same `skills/` content through thin adapters. Do not maintain client-specific
forks of a skill.

`CLAUDE.md` must remain a verbatim copy of this file.

## Repository map

- `skills/<name>/SKILL.md` — active, discoverable skills.
- `.claude-plugin/`, `.codex-plugin/`, `.cursor-plugin/`, `.opencode/`,
  `.github/` — thin client adapters, not alternate protocol sources.
- `scripts/validate_skills.py` — portable structure and suite validator.
- `tests/` — deterministic and behavioral regression gates.
- `assets/` — shared public brand assets.
- `docs/COMPATIBILITY.md` — client proof levels and clean-session acceptance.
- `docs/TESTING.md` — deterministic, behavioral and runtime evidence layers.
- `.github/workflows/validate.yml` and `.github/*_TEMPLATE*` — public CI and
  contribution intake, not alternate workflow truth.

## Skill format

Every active skill lives at `skills/<skill-name>/SKILL.md` and starts on line 1:

```yaml
---
name: skill-name
description: "Use when ..."
---
```

Rules:

- `name` is lowercase kebab-case and equals the directory name.
- Shared frontmatter contains only `name` and `description`.
- Description says when to trigger and when useful includes the short `nb-*`
  alias. Aliases are trigger phrases, not duplicate skill directories.
- Keep the body operational and portable. Put long templates in
  skill-relative `references/`; put deterministic helpers in `scripts/`.
- Use relative links within a skill. Never depend on one user's filesystem.

## NoBrainer delivery contract

For non-trivial work use:

`outcome -> evidence -> design/spec -> plan -> implementation -> verification -> audit`

1. Read the actual checkout, nearest instructions, dirty state, source of truth,
   tests and available runtime before planning.
2. Define the observable outcome, audience, scope, exclusions, quality criteria,
   owner gates and proof of completion.
3. Ask one focused requirements round only when the answer changes scope,
   architecture or safety. Otherwise make the smallest safe assumption and say
   what it was.
4. Implement the smallest reversible change. Preserve unrelated work.
5. Verify with fresh target-workflow evidence. Static checks, local runtime,
   production, buyer usefulness and external delivery are different proof levels.
6. Treat every delegated `FINISHED` as an audit input, never as proof.
7. Report outcome, checks, uncertainty, rollback and one next action.

A timeout, partial output, schema error, dead session, exhausted retry, failed
test or inaccessible runtime is not success.

## Tibo operating model

Start with the result and the human's attention, not with model or tool choice.
Classify execution as one product:

- `BUDDY`: a short interactive requirements/decision gate while the owner is in
  the flow. It ends when outcome and acceptance are clear.
- `AUTOPILOT`: bounded autonomous execution after `READY_GATE`, with a state
  owner, trigger/input/output contract, stop condition, idempotence/resume,
  retry budget, evidence and rollback.

Do not hide both inside an opaque `continue until done` loop. AUTOPILOT does not
authorize merge, deploy, publishing, spending, deletion, credentials, production
mutation or weaker safety controls.

For non-mechanical work define content quality before execution:

- purpose and audience;
- correctness sources/checks;
- required completeness and exclusions;
- coherent terminology and structure;
- human or target-workflow review when quality is subjective.

`FINISHED` is invalid while required quality is unassessed. Distinguish observed
facts, attributed claims, inference, recommendation and forecast.

Protect attention: default to one primary agent, batch routine progress, surface
urgent blockers, and add workers only for independent bounded work with a
measurable latency or isolation benefit. A practical starting ceiling is 2–4
workers, not an expanding swarm.

## NoBrainer Ultra and sessions

Use `nobrainer-ultra` for non-trivial end-to-end delivery. Its lifecycle is:

`DRIFT_CHECK -> BUDDY -> READY_GATE -> AUTOPILOT -> VERIFY -> RECEIVE_AUDIT`

Keep a coherent task in `<repo> | MAIN`. Use `nobrainer-sessions` only when
visible handoff, isolated checkout, resume, independent parallel work or a warm
specialist justifies coordination.

Session titles help the owner navigate. Exact thread/host identity, checkout,
commit, task, write scope, lease and readback establish truth. One writer owns
shared sequential state. A Markdown lease is advisory; never claim atomic
fencing without an enforcing control plane.

Workers receive one bounded work unit, never choose a successor, and return one
report. MAIN independently audits the exact session, diff, tests, evidence and
released lease before one canonical state transition.

## Specs, wiki and durable state

Use `nobrainer-spec-driven-development` only when ambiguity, architecture,
public contracts, migrations, difficult rollback, dependent components or
cross-session work justify a durable spec. A spec defines what must be true; a
plan orders work.

Use `nobrainer-wiki` only for durable knowledge reused across tasks. Wiki pages
do not hold live execution state, leases, current hashes or transient blockers.
Preserve raw sources, curated knowledge, map/rules and inbox/history as distinct
concerns. Never store secrets.

One fact has one canonical owner. Link between spec, plan, execution state,
reports and wiki; do not duplicate mutable status across them.

## Lightweight learning loop

Continuous improvement beats delayed perfection: deliver the smallest safe,
verified increment, then improve the measured bottleneck. This does not waive
acceptance, tests, owner gates or proof. A clear daily task stays in one session
without SDD, a wiki, workers or an evaluation loop unless one has a concrete
benefit.

After an owner correction or newly verified fact, classify it before persisting:

- transient clarification stays in the current task;
- an explicit reusable preference, decision or fact may go through
  `nobrainer-wiki` mode `ADD`, with source, date, scope and confidentiality;
- a repeatable behavior gap becomes a regression scenario and may route to
  `nobrainer-autoimprove`;
- a durable repository rule may receive one minimal instruction change with a
  diff, verification and rollback.

Do not infer a permanent user trait from one interaction, load an entire wiki
when a targeted query is enough, or silently self-modify global instructions.
Personalization must remain inspectable, correctable and bounded by the same
public/private and secret boundaries as its source.

## Superpowers boundary

Official Superpowers is an external dependency for brainstorming, planning,
worktrees, TDD, systematic debugging, execution, implementation review methods
and verification.
NoBrainer owns lifecycle, visible sessions, owner gates, spec contracts,
decision/RCA records, measurable improvement and durable knowledge.

Use the current official plugin for each harness. Do not vendor, rename, fork or
copy Superpowers skills here. If a required capability is unavailable, report
the missing dependency and one installation/repair action.

## Skill portfolio and discovery

The active directory is the complete nine-skill product. Every active directory
uses the `nobrainer-` prefix and must own a recurring cross-project boundary;
stack-, account-, client- and task-specific helpers stay out. Do not promote a
skill because it is popular or already exists. The active decisions and
retirement tests live in `docs/SKILL_CURATION.md`.

Do not add an always-installed wrapper for community discovery. Ultra may use
the official `skills` CLI only after the curated suite and first-party
capabilities leave a real gap. External skills are untrusted: inspect the exact
source/ref, instructions, scripts, permissions, network/credential behavior,
trigger overlap and rollback. Persistent/global installation or script execution
requires owner approval.

## Browser evidence boundary

Prefer a task-native API, MCP or first-party CLI when it exposes the required
state directly. When rendered behavior matters or no suitable structured path
exists, route to `nobrainer-browser`: use the current official
`@playwright/cli`, attach to an already approved Chromium session only when its
login/state is required, and use the repository's Playwright runner for tests
and trace evidence. Inspect DOM snapshots, network, console and the resulting
state; preserve and open the actual trace instead of trusting a green exit code.

Do not add a browser plugin, a second automation stack or Playwright MCP merely
to duplicate the CLI. Installation, extension attach, authentication and every
consequential browser action remain explicit scope or owner gates.

## Changing a skill

Follow the local `skill-creator` and official Superpowers writing-skills method:

1. Inspect existing patterns and dependencies.
2. Write a pressure scenario and observe the baseline failure or gap (`RED`).
3. Make the smallest skill change.
4. Re-run the same scenario and deterministic validators (`GREEN`).
5. Add adversarial/non-trigger cases and verify links, scripts and public-clean
   boundaries.
6. Review the diff and run `nobrainer-autoimprove` only when a frozen eval can
   measure a meaningful gain without overfitting.

Do one skill at a time. Generator/reviewer independence matters more than raw
agent count. Preserve eval inputs and report null results honestly.

Required baseline commands:

```bash
python3 scripts/validate_skills.py
python3 scripts/validate_skills.py --suite
python3 -m unittest discover -s tests -v
gitleaks git --pre-commit --staged --redact --no-banner --ignore-gitleaks-allow
```

Run every changed skill's scripts or syntax checks and the relevant client
adapter readback. Do not claim marketplace, install or runtime compatibility
from JSON parsing alone. Use the proof levels and clean-session protocol in
`docs/COMPATIBILITY.md`; use `docs/TESTING.md` for the release evidence boundary.

## Public-clean and safety

- No credentials, tokens, cookies, seed phrases, personal data, private client
  names, internal hosts, account IDs or secret-bearing examples.
- No machine-specific absolute paths in skills or public docs.
- In shell snippets, never use angle-bracket placeholders that execute as
  redirection. Use named environment variables or `/path/to/example`.
- Do not hardcode model names, versions, prices or client capabilities when they
  can drift; detect or document verification date and limits.
- Treat public/agent-generated input as untrusted. Sanitize paths, URLs, logs and
  report fields before persistence.
- Do not silently publish, spend, contact people, delete data, alter credentials,
  merge, deploy or mutate production.

## Golden engineering rules

1. Simplicity first: the smallest complete design wins.
2. YAGNI before abstraction: build for the current proven need.
3. DRY knowledge, not accidental textual similarity.
4. Find root causes; do not stack symptom patches.
5. Reuse mature capabilities before adding dependencies or custom machinery.
6. Keep concerns modular and state ownership explicit.
7. Fail loudly at boundaries; never convert uncertainty into a green status.
8. Comments explain non-obvious why, constraints or tradeoffs, not visible code.
9. Configuration owns values that vary by environment, account or run.
10. Deletion or compatibility breaks require proof that no state, money, public
    contract or active consumer depends on the removed path.

## Git and handoff

- Never commit directly to `main`. Use a focused branch and PR.
- Keep unrelated user changes and untracked files out of the patch.
- Do not commit, push, open a PR, merge or publish unless the current task
  authorizes that external state change.
- Before handoff show the scoped diff, validators, behavioral evidence, known
  unverified adapters and rollback.
