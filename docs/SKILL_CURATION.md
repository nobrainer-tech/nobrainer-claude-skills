# Skill curation audit

Reviewed: 2026-08-27

This repository is a deliberately small product, inspired by Superpowers'
focused skill boundaries. Every active skill must be useful in ordinary
high-quality delivery, own a distinct decision boundary and justify its trigger.
Task-, account-, stack- and client-specific helpers do not stay active merely
because they once worked.

## Admission rules

Keep a skill only when all are true:

- it solves a recurring cross-project problem;
- its trigger and stop condition are distinct;
- it does not duplicate another NoBrainer skill, Superpowers or a first-party
  tool;
- the instructions are small enough to audit and maintain;
- it has deterministic contract tests or a repeatable pressure scenario;
- its safety, evidence and rollback boundaries are explicit.

Good engineering, anti-slop, secret handling, owner gates and verification are
shared contracts inside the suite and repository instructions. They are not
separate always-loaded skills.

## Final active set

| Skill | Why it remains |
|---|---|
| `nobrainer-ultra` | Master setup and delivery workflow: Tibo-inspired attention model, short requirements gate, routing, guarded autonomy and final audit. |
| `nobrainer-sessions` | Visible named multi-session work, exact identity, writer ownership, audited handoff and recovery. |
| `nobrainer-spec-driven-development` | Durable contract and acceptance ledger when architecture, migrations, dependent phases or resumability justify SDD. |
| `nobrainer-wiki` | One Karpathy-inspired LLM-wiki owner with setup, read-only query, explicit capture and audit/apply modes. |
| `nobrainer-browser` | Thin Playwright-first boundary for rendered UI, approved-session attach, browser tests and trace evidence. |
| `nobrainer-autoimprove` | Karpathy-inspired measured baseline/variant/eval/holdout loop with keep-or-revert. |
| `nobrainer-decide` | Consequential evidence-based decisions with alternatives, attack and cold review. |
| `nobrainer-rca` | Read-only causal diagnosis with a continuous evidence chain and explicit stop before fixes. |
| `nobrainer-review` | One evidence-gated closeout, bug-hunt and release-review owner that reports only verified actionable findings. |

All active names use the `nobrainer-` prefix. Short `nb-*` forms are trigger
aliases in frontmatter, never duplicate directories.

## Removed from active discovery

- `agents-restraint`: anti-overengineering and concise project-instruction rules
  moved into `nobrainer-ultra`, `nobrainer-review` and repository instructions.
- `nobrainer-wiki-add`, `nobrainer-wiki-get`, `nobrainer-wiki-tidy`: folded into
  explicit modes of the single `nobrainer-wiki` owner.
- `deep-audit`, `deep-autoreview`, `deep-bugs-finder`: reduced to one rebranded
  `nobrainer-review`; the 1,000+ line custom multi-model harness was removed in
  favor of maintained native review capabilities.
- `add-gitleaks`: secret scanning remains enabled for this repository, but
  installing Gitleaks into arbitrary projects is not a universal agent skill.
- `nobrainer-fast-audit`, `nobrainer-npm-secure`: broad/stack-specific security
  work should use the target's current first-party tooling or a reviewed
  specialist when actually needed.
- `codex-in-claude-code`, `nobrainer-reddit`: client/account integrations are not
  universal workflow skills.
- Earlier monolithic autopilot, fixed ten-agent RCA, old browser stack,
  duplicate memory/wiki wrappers, 401-agent catalog, Ultracode and old Karpathy
  wrapper names remain absent and recoverable from Git history.

## Dynamic specialist policy

Do not add a permanent “find skills” wrapper. `nobrainer-ultra` owns the fallback:

1. the nine reviewed NoBrainer skills;
2. an existing first-party project tool, API, CLI or native client capability;
3. [`npx skills find`](https://github.com/vercel-labs/skills) only for a real
   missing specialist capability;
4. one-off `npx skills use` evaluation before persistent installation.

An external skill is untrusted input regardless of popularity. Inspect its exact
source/ref, body, scripts, license, permissions, network/credential behavior,
write scope, trigger overlap and rollback. Prefer immutable, project-local and
reversible use. Persistent/global installation and script execution require an
explicit owner gate.

## Re-review trigger

Re-run this audit when two skills route the same request, a native tool replaces
a contract, a skill repeatedly produces noise, or a missing specialist recurs
across unrelated projects. Additions require a failing pressure scenario and
proof that extending an existing owner would be worse than a new trigger.
