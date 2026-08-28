# Testing and evaluation

The repository uses four evidence layers. A green lower layer never proves a
higher one.

## 1. Structure and public safety

- portable frontmatter, directory/name identity and exact active inventory;
- relative companion links and retired-name exclusion;
- public-clean text, manifest parsing and version consistency;
- installer conflict refusal, idempotence, readback, race-safe atomic restore and
  preserved migration/rollback recovery claims;
- secret scanning before publication.

Run:

```bash
python3 scripts/validate_skills.py
python3 scripts/validate_skills.py --suite
```

## 2. Deterministic behavior contracts

Unit tests pressure the routing and safety invariants that can be checked
without an LLM: Ultra states, session identity and lease gates, SDD boundaries,
trigger ownership, browser routing, adapter registration and installer races.
Adapter tests execute every bootstrap mechanism that can run locally: the Claude
and Cursor SessionStart JSON shapes, OpenCode injection/deduplication, and Pi
discovery plus post-compaction re-injection. They also parse the portable Agent
Plugin, Gemini and Kimi manifests, reject invented Devin/Hermes adapters and
enforce the exact fifteen-skill inventory, correction hooks and workflow
diagram contract.

```bash
python3 -m unittest discover -s tests -v
```

GitHub Actions runs these deterministic layers on Linux and macOS. It checks
Python, Node and shell syntax plus deterministic adapter contracts, and runs a
checksum-pinned Gitleaks tree scan on Linux. CI does not claim a client UI or
model followed a skill.

## 3. Forward behavior evaluation

Behavior-shaping changes need a frozen scenario set, an unchanged baseline and
an independent judge. Keep development cases separate from final holdout cases;
do not tune against a failed holdout. Record accepted findings, null results,
digest, rollback and any model/harness substitutions.

The current changed-control records are
[`evals/dispatcher-routing-v1.2.0-2026-08-28.md`](evals/dispatcher-routing-v1.2.0-2026-08-28.md)
and
[`evals/writing-density-v1.2.0-2026-08-28.md`](evals/writing-density-v1.2.0-2026-08-28.md).
The broader v1.1 routing baseline remains in
[`evals/core-routing-v1.1.0-2026-08-28.md`](evals/core-routing-v1.1.0-2026-08-28.md).
Do not mix scores across changed inventories, prompts or rubrics.

## 4. Client runtime acceptance

A client becomes runtime-verified only after a clean-session transcript proves
discovery and correct first actions. Follow
[`COMPATIBILITY.md`](COMPATIBILITY.md). Marketplace publication, production
behavior and buyer usefulness each require their own readback.

## Release gate

A releasable commit requires:

- all deterministic checks green on the exact commit;
- no unresolved P0/P1 review finding;
- a public-clean and secret scan;
- a recorded behavior holdout for changed workflow controls;
- a review-failure scenario proving the route returns to Build with invalidated
  evidence;
- honest compatibility labels;
- a rollback path;
- owner approval for merge and publication.

Scan the exact staged candidate with:

```bash
gitleaks git --pre-commit --staged --redact --no-banner --ignore-gitleaks-allow
```

A full-history finding is a separate history-remediation decision. Investigate
it explicitly; do not hide it behind a broad allowlist or treat it as proof that
the staged candidate introduced a secret.
