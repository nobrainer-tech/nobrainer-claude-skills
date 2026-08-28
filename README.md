<p align="center">
  <a href="https://nobrainer.tech">
    <img src="assets/nobrainer-tech-logo.svg" width="120" alt="NoBrainer.tech logo">
  </a>
</p>

<h1 align="center">nobrainer-tech-skills</h1>

<p align="center">
  Lightweight, portable agentic workflows for fast and evidence-gated delivery.
</p>

<p align="center">
  <a href="https://github.com/nobrainer-tech/nobrainer-tech-skills/actions/workflows/validate.yml"><img alt="Validation" src="https://github.com/nobrainer-tech/nobrainer-tech-skills/actions/workflows/validate.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/license-MIT-27d8cf.svg"></a>
</p>

<p align="center">
  <a href="https://nobrainer.tech">NoBrainer.tech</a>
  ·
  <a href="https://nobrainertech.gumroad.com">Production-ready agentic workflows</a>
</p>

Give the agent one outcome. `nobrainer-ultra` inspects the real project, asks at
most one focused requirements round, builds a complete skill-routed execution
map, creates a minimal specialist team when it will genuinely help, and drives
the approved work until verified delivery or a real owner gate.

![NoBrainer Ultra workflow: one clarification round, a skill-routed execution map, build, review, verification, delivery and durable learning; failed review returns to build](assets/nobrainer-workflow.svg)

**Continuous improvement beats delayed perfection.** A small task stays small.
A non-trivial task gets enough structure to be reliable, but no speculative
framework, automatic swarm or documentation theatre.

## Start with one skill

Use [`nobrainer-ultra`](skills/nobrainer-ultra/) (`nb-ultra`) for setup or any
non-trivial outcome:

```text
DRIFT_CHECK -> BUDDY -> EXECUTION_MAP -> READY_GATE -> AUTOPILOT
            -> VERIFY -> RECEIVE_AUDIT -> LEARN
```

- `BUDDY` is the first and only ordinary clarification stage.
- `EXECUTION_MAP` is the complete TODO: every stage has one owning skill or
  capability, dependencies, write scope, evidence, session and owner gate.
- `AUTOPILOT` continues through routine approved work without repeated check-ins.
- `nobrainer-team` selects the minimum useful capabilities;
  `nobrainer-dispatcher` schedules only approved ready work in bounded batches;
  `nobrainer-sessions` creates or reuses exact visible sessions only when
  parallelism, isolation, handoff or independent evidence earns the cost.
- Failed review returns to `nobrainer-build`; changed code invalidates old proof.
- Merge, deploy, publishing, spending, credentials, destructive operations and
  production mutation remain owner gates unless exact authority is already
  recorded.

The two execution axes stay independent:

```text
CONTROL_MODE: BUDDY -> AUTOPILOT
SESSION_MODE: MAIN | MULTI_SESSION
```

Autopilot can run in one MAIN session. A multi-session plan is not automatically
autonomous. This keeps the workflow understandable and avoids agent theatre.

## Fifteen skills, distinct ownership

Aliases are trigger phrases, not duplicate directories. Each skill owns one
recurring boundary:

| Skill | Alias | Responsibility |
|---|---|---|
| [`nobrainer-ultra`](skills/nobrainer-ultra/) | `nb-ultra` | End-to-end setup and delivery: one requirements gate, complete execution map, autopilot, audit and learning |
| [`nobrainer-team`](skills/nobrainer-team/) | `nb-team` | Minimal capability roster, installed-skill inventory and safe temporary specialist discovery |
| [`nobrainer-dispatcher`](skills/nobrainer-dispatcher/) | `nb-dispatcher` | Dependency-aware ready-set scheduling, bounded dispatch, backpressure and audited result routing |
| [`nobrainer-research`](skills/nobrainer-research/) | `nb-research` | Bounded current research from primary sources with facts separated from inference |
| [`nobrainer-writing`](skills/nobrainer-writing/) | `nb-write` | High-signal drafting, compression and editing that preserve meaning, evidence, voice and action |
| [`nobrainer-build`](skills/nobrainer-build/) | `nb-build` | Smallest verified implementation using calibrated KISS, DRY, SOLID, YAGNI and anti-slop gates |
| [`nobrainer-security`](skills/nobrainer-security/) | `nb-security` | Threat models, security review, supply-chain audit and high-risk release evidence |
| [`nobrainer-sessions`](skills/nobrainer-sessions/) | `nb-sessions` | Named visible sessions, exact identity, isolated writers, audited handoff, lease and recovery |
| [`nobrainer-spec-driven-development`](skills/nobrainer-spec-driven-development/) | `nb-sdd` | Durable specification and acceptance ledger when contracts, risk or resumability justify it |
| [`nobrainer-wiki`](skills/nobrainer-wiki/) | `nb-wiki` | Targeted retrieval and sourced durable knowledge without hidden memory or live task state |
| [`nobrainer-browser`](skills/nobrainer-browser/) | `nb-browser` | Playwright-first rendered inspection, approved session attach, browser tests and trace evidence |
| [`nobrainer-autoimprove`](skills/nobrainer-autoimprove/) | `nb-autoimprove` | Measured baseline/variant/eval/holdout improvement with keep-or-revert |
| [`nobrainer-decide`](skills/nobrainer-decide/) | `nb-decide` | Consequential decisions with different-shaped options, scoring, attack and one commitment |
| [`nobrainer-rca`](skills/nobrainer-rca/) | `nb-rca` | Read-only causal diagnosis with a continuous evidence chain and explicit uncertainty |
| [`nobrainer-review`](skills/nobrainer-review/) | `nb-review` | Acceptance trace, adversarial bug hunt and release close gate without speculative findings |

The [curation audit](docs/SKILL_CURATION.md) records why each skill exists and
what belongs in another skill instead of becoming a sixteenth trigger.

## Correct once, improve permanently

Ultra contains portable semantic hooks for four events:

- `OWNER_DECISION_CHANGED` updates the canonical decision, marks the old value
  superseded and invalidates dependent TODO items and evidence;
- `AGENT_ERROR_CORRECTED` fixes the active result and classifies one minimal
  prevention candidate: `AUTO_SCOPED` may persist it to one governed canonical
  project-local store, `ASK` prepares one exact diff, and `OFF` keeps it
  task-local without a durable diff;
- `REVIEW_FAILED` creates a bounded Build correction and sends fresh evidence
  back to Review;
- `REPEATED_DEFECT` stops blind retries and invokes RCA with the prior failure
  fingerprint.

Only durable, sourced, authorized and non-secret knowledge is promoted through
`nobrainer-wiki`. One mutable fact has one canonical owner; the system does not
append contradictory copies to the plan, instructions and wiki.
Project setup records `LEARNING_WRITE_POLICY: AUTO_SCOPED | ASK | OFF`, so an
owner can enable automatic project-local learning without granting global or
publishing authority.

## Quality without AI slop

The shared delivery contract operationalizes:

- `KISS`: the simplest complete design wins;
- `YAGNI`: no speculative extension points or future options;
- `DRY`: deduplicate owned knowledge and state, not incidental similarity;
- `SOLID`: cohesive responsibilities and stable boundaries without class or
  interface ceremony;
- evidence: no invented APIs, fake runtime claims, placeholder logic, swallowed
  errors, generic prose, broad unrelated rewrites or mock-only confidence;
- content quality: purpose, audience, correctness sources, completeness,
  coherence and target-workflow usefulness are frozen before execution.

If a decision-relevant fact may be current, niche, uncertain, high-stakes or
source-attributed, Ultra routes the smallest sufficient check through Research.
If primary evidence is unavailable, it says `RESEARCH_BLOCKED` instead of
guessing.

## Compatibility is a proof ladder

All clients consume the same `skills/` tree. Thin adapters cover Claude Code,
Codex, Cursor, OpenCode, Gemini CLI, Kimi Code and Pi; the portable Agent Plugin
manifest and project instructions are the fallback for other Agent Skills
consumers.

Compatibility claims use five distinct levels:

```text
SOURCE_VALIDATED -> REPOSITORY_CHECKED -> CLIENT_LOADED
                 -> RUNTIME_VERIFIED -> DISTRIBUTED
```

A valid manifest does not prove clean-session routing. A local test does not
prove production. See [Compatibility](docs/COMPATIBILITY.md) for current proof
and [Testing](docs/TESTING.md) for acceptance evidence.

## Install safely

Clone a reviewed ref, validate it, preview exact targets, then apply:

```bash
test -n "${NB_REVIEWED_REF:-}"
git clone https://github.com/nobrainer-tech/nobrainer-tech-skills.git
cd nobrainer-tech-skills
git checkout --detach "$NB_REVIEWED_REF"
test "$(git rev-parse HEAD)" = "$(git rev-parse "$NB_REVIEWED_REF^{commit}")"
python3 scripts/validate_skills.py --suite
python3 scripts/install_skills.py --client codex
python3 scripts/install_skills.py --client codex --apply
```

Set `NB_REVIEWED_REF` to the exact release tag or full commit you reviewed; the
snippet intentionally stops when it is unset or does not resolve to that commit.

The installer defaults to all fifteen canonical skills, supports an exact
subset, refuses foreign targets and can use links or copies. Restart the client
and perform clean-session discovery before claiming runtime installation. Full
client-specific steps and rollback are in [Installation](docs/INSTALL.md).

Version `v1.2.0` is a release candidate until its tag, CI, downloaded archive
and isolated fifteen-skill install are read back. The latest published source
release remains [`v1.1.0`](docs/releases/v1.1.0.md). To reproduce that release:

```bash
git checkout --detach d6931a1006bf0180955d8437fd93174b6a512428
test "$(git rev-parse HEAD)" = "d6931a1006bf0180955d8437fd93174b6a512428"
python3 scripts/validate_skills.py --suite
```

GitHub reports the release and tag as mutable, so security-sensitive consumers
should pin that full commit SHA. `v1.0.0` remains the previous rollback anchor.

## One source, thin adapters

```text
skills/               canonical portable behavior
adapters/bootstrap.md small session-start route to Ultra
hooks/                tested client lifecycle adapters
scripts/              validation and conflict-safe installation
tests/                deterministic and behavior-contract gates
docs/                 compatibility, curation, eval and release evidence
assets/               brand and workflow diagrams
```

Client-specific forks of a skill are prohibited. External skills discovered by
Team are untrusted input: inspect the exact source/ref, instructions, scripts,
permissions, network/credential behavior, trigger overlap and rollback. Prefer
temporary project-scoped use; persistent or global installation is an owner
gate.

## Attribution

- `nobrainer-autoimprove` is an independent adaptation of Andrej Karpathy's
  [autoresearch](https://github.com/karpathy/autoresearch) measure-change-keep
  loop.
- `nobrainer-wiki` is an independent adaptation of Andrej Karpathy's
  [LLM wiki concept](https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f).
- Other external design sources remain cited inside the exact skill where they
  influenced a behavior contract.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and
[RELEASE-NOTES.md](RELEASE-NOTES.md). Every change goes through a focused PR,
pressure scenario, validators, diff review and secret scan. Do not report
publication, distribution, live routing or user-visible success without
readback from that layer.

NoBrainer Tech builds practical agentic workflows for teams that want speed
without surrendering control. Learn more at [nobrainer.tech](https://nobrainer.tech)
or browse ready-to-use workflow products on
[Gumroad](https://nobrainertech.gumroad.com).
