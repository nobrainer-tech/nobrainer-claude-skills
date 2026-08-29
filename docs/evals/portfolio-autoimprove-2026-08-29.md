# Portfolio autoimprove audit — 2026-08-29

## Scope and method

This record audits the public `nobrainer-tech-skills` package at baseline
commit `44f6e27f0492d7a3cc03cfe812bbe30cdd54bd25`. The frozen target is the
portable behavior of all fifteen active skills, their routing boundaries, the
shared instructions and the deterministic acceptance suite.

The audit applies the `nobrainer-autoimprove` contract per skill:

1. frame one observable target and its write scope;
2. inspect the unchanged baseline and record a pressure case;
3. run hard gates before judging quality;
4. start a bounded candidate/holdout loop only when a falsifiable gap and a
   measurable acceptance check exist;
5. keep the baseline on a null result and never promote from prose preference.

The per-skill baseline is the exact file hash below plus the repository's
frontmatter, link, public-clean and contract checks. This is a structural and
instruction-quality audit. It does not prove that every future model follows a
skill, that a client discovers it, or that a production workflow is faster.

## Per-skill results

`NO_CHANGE` means the skill was still audited, but its existing contract had no
reproducible material gap worth a mutation loop. It is a valid null result, not
an unverified claim that the skill is perfect. The full candidate loop was
reserved for the three gaps that could change the package's observable control
behavior.

| Skill | Baseline SHA-256 | Frozen pressure target | Autoimprove result | Decision |
|---|---|---|---|---|
| `nobrainer-ultra` | `aa14995abe77e92d1b03851a05a9e857eeff0963e581b2d1731587a1f2489f3a` | Visible TODO/goal state after each auditable transition | `PROMOTED` after development and holdout contract checks | Add one `GOAL_LOOP` pointer owned by the execution map |
| `nobrainer-team` | `38cbda8dcdecbe4c5b6a6d942d13114455ad5e4b897e58e7dcb68bcba04ee629` | Minimum roster, capability provenance, untrusted external skill and owner gate | `NO_CHANGE` | Existing boundary is specific and tested |
| `nobrainer-dispatcher` | `5be28a908cb5e467b230205f6e3bf5f35c508b4aa0e2bcaeaae0aa398badf89b` | Ready-set, dependency, writer, backpressure, retry and audited result routing | `NO_CHANGE` | Existing hash-bound holdouts and suite cover the material risk |
| `nobrainer-research` | `53abe68752c8285c352924db05adf5775b10ca76879a8de81791b2891d575d04` | Problem gate: targeted wiki, current internet, fact/inference split and blocked state | `NO_CHANGE` | Existing bounded current-source contract is sufficient |
| `nobrainer-writing` | `a756274e8a55cf32c7f2f15e2502801bcd7b31f30682d787646c81adee46dcda` | High-signal text without dropped conditions, invented facts or detector gaming | `NO_CHANGE` | Existing ten-source research and release holdout already cover the target |
| `nobrainer-build` | `fe1f2d2e98fcc15be7ffc622749b542d8f807f6f90ac1ab78dde0b686add36b0` | Smallest verified patch, KISS/DRY/SOLID/YAGNI and anti-slop gate | `NO_CHANGE` | Existing start, engineering, proof and stop gates are distinct |
| `nobrainer-security` | `f4462fef42113ae55d36badc816b3b1f83b869f89e20e417918a8570be08ee78` | Trust boundary, read-only default, false-positive filter and remediation gate | `NO_CHANGE` | No isolated material omission found |
| `nobrainer-sessions` | `8b9a78ee578901e7bc74db3cd2040808a4d0368b40ddaf327d30ccdf79fd837f` | Exact visible identity, writer/lease, one report, receive-audit and recovery | `NO_CHANGE` | Existing protocol already fails closed on identity and lease uncertainty |
| `nobrainer-spec-driven-development` | `b59513c0d89354ee62a77bc51da62c2ff6c13ab1f1b1225e14f14d82e73e12d7` | Persist only a durable contract with acceptance and rollback | `NO_CHANGE` | Existing threshold prevents specification theatre |
| `nobrainer-wiki` | `925bb17109dfa12345f04e25c4d0a0f1fcaec7c8264a85a51e328a512041d2b9` | Targeted retrieval, sourced durable capture and secret/classification boundary | `NO_CHANGE` | Existing single-owner and raw-source separation are adequate |
| `nobrainer-browser` | `e89967190f7f76d6f2dde698764474c053868e84e872e9bfec5e9ea816610393` | Playwright CLI, approved attach, rendered evidence and traces | `NO_CHANGE` | Existing CLI-first route and no-default-plugin gate are adequate |
| `nobrainer-autoimprove` | `50ee757b9fa7ba6434eeba56d90713f60bcdf7217e2cad6206e5ca35c9d272d5` | Unambiguous promotion/null/revert outcome for a bounded experiment | `PROMOTED` after contract holdout checks | Add explicit promotion outcome and Ultra state-update handoff |
| `nobrainer-decide` | `eefba77074f3aea96bdd2bf2c2101207a2ab2288a0942ba92d682117ab9d9041` | Different-shaped options, transparent scoring, attack and commitment | `NO_CHANGE` | Existing rigor calibration and cold review cover the boundary |
| `nobrainer-rca` | `604d0bb88dba5f820760b5d653ccf2dd732135c3198778c846424d72fe7deea9` | Continuous causal evidence chain before a fix | `NO_CHANGE` | Existing investigation contract stops speculation and blind retry |
| `nobrainer-review` | `74c2b0d23e52919d8ed3fec2cf70dc4218a6519d0645c9ba778928e53e733337` | Pre-read falsifiable predictions and explicit symbol/path verification | `PROMOTED` after development and holdout contract checks | Restore the two high-value portable omissions from the deep audit |

The three promoted rows use the same four-point structural eval in baseline and
candidate form: `nobrainer-ultra` `0/4 -> 4/4`, `nobrainer-review` `0/4 -> 4/4`,
and `nobrainer-autoimprove` `0/4 -> 4/4`. The points are literal contract
assertions, not a subjective model score; the final full suite is the protected
holdout. The exact four assertions for each candidate are listed in the next
section so the promotion claim is reproducible.

## Deep-audit coverage decision

The existing `nobrainer-review` already covered the high-value portable core:
re-opening current files, acceptance/backward tracing, callers/consumers,
renamed symbols and imports/exports, concrete value paths, adversarial edges,
retry/race/auth/rollback checks, actionable-finding filtering and fresh
re-check after fixes. Its description and installer already route the legacy
`deep-audit` and related review invocations to this owner.

The baseline omitted two useful, portable controls. The candidate restores them:

- write two or three falsifiable defect predictions before implementation
  details are read, then classify them `HIT`, `MISS` or `UNTESTED` with evidence;
- run and report a literal `NAME_PATH_AUDIT` for new or renamed symbols,
  imports, exports, configuration keys and migrations, or explicitly mark it
  `NOT_APPLICABLE`.

The audit deliberately does not copy a blanket line-by-line ritual, a
language-specific command matrix, unsupported client-specific tooling or a
second review swarm. Those are either owned by the project's verifier/Build,
not portable across clients, or add ceremony without a demonstrated control
gain. The final Review finding gate remains the authority for reporting a bug.

## Frozen candidate/holdout checks

For each candidate, the evaluator reads the baseline blob at the recorded
commit and the current candidate file, normalizes only whitespace, and counts
the same four literal contract assertions. The development result is
`0/4 -> 4/4` for all three candidates. The candidate then goes through the
complete protected suite; no promotion is valid if that holdout fails.

- `nobrainer-ultra`: `GOAL_LOOP`; `TODO_PROGRESS`; the map is the sole mutable
  TODO owner; a stale summary cannot authorize a successor.
- `nobrainer-review`: pre-read predictions; `NAME_PATH_AUDIT`; the `HIT`/
  `MISS`/`UNTESTED` outcome; the green-test limitation.
- `nobrainer-autoimprove`: the four-valued `PROMOTION` field; the
  `HOLDOUT_RESULT` field; the `NO_CHANGE` rule; the `REVERTED` rule.

The evaluator command was a read-only Python comparison of those exact strings
against baseline commit `44f6e27f0492d7a3cc03cfe812bbe30cdd54bd25` and the
candidate files. It returned `0/4 -> 4/4` for each row. This is a structural
contract score, not a claim about model obedience or end-user productivity.

## Whole Ultra-flow evaluation

The frozen whole-flow pressure cases were:

| Case | Expected control behavior | Result |
|---|---|---|
| Clear small request | Stay in `MAIN`; no SDD, wiki, team, dispatcher or evaluation loop without a concrete benefit | PASS |
| Non-trivial request | One `BUDDY` round, complete `EXECUTION_MAP`, visible `GOAL_LOOP`, then bounded `AUTOPILOT` | PASS |
| Independent work units | Team first, then Dispatcher only when a queue exists, Sessions for exact transport, and receive-audit before release | PASS |
| Failed review | Return to Build, invalidate stale proof, rerun review and receive-audit, update TODO/goal before routing | PASS |
| Changed owner decision | Supersede the old requirement, stop affected rows, preserve dependants blocked, re-plan under a new fingerprint | PASS |
| Problem or uncertainty | Query relevant wiki, perform current research, reconcile runtime; use `RESEARCH_BLOCKED` rather than guess | PASS |
| No remaining work | Mark the goal `COMPLETE` and stop; do not invent a successor | PASS |

The baseline had the same lifecycle and correction hooks but did not require a
visible, synchronized goal snapshot after each transition. That was the single
whole-flow gap promoted. The map remains the only mutable TODO owner, so the new
goal block improves observability without creating a second state ledger.

## Fresh post-change review

The review was repeated after the candidate edits with the complete changed
surface in scope. The pre-read predictions were:

- `MISS`: `GOAL_LOOP` becomes a second mutable TODO owner. The Ultra contract,
  root instructions and tests all assign mutation to the map only.
- `HIT -> FIXED`: historical hash-bound evidence could be checked only against
  current bytes. The test now checks the packet against its frozen source
  hashes and separately proves that the current Ultra is different.
- `MISS`: the new Review and Autoimprove fields are merely descriptive. Their
  presence and current source hashes are checked by the contract tests and the
  portfolio audit test.

`NAME_PATH_AUDIT: PASS`: literal `rg` checks found every new field and
reference in the owning skill, the relevant instructions, the portfolio record
and tests; no new alias directory or renamed active skill was introduced.

`REVIEW_VERDICT: CLEAN` for the reviewed scope. No speculative finding was
promoted. The earlier sidecar attempts were unavailable and are not part of
this verdict.

## Hard gates and evidence

Candidate hard gates:

- all active skills retain portable line-1 frontmatter and directory/name parity;
- no new skill, alias directory, private path, secret, client fork or duplicate
  state owner;
- `AGENTS.md` and `CLAUDE.md` remain byte-identical;
- bootstrap remains within its 190-word budget;
- historical hash-bound packets are either preserved as historical evidence or
  explicitly marked stale after a contract change;
- focused tests, complete tests, repository validator, skill validator, syntax,
  diff and secret checks pass before promotion.

The three promoted candidates are intentionally small and reversible. Their
baseline hashes above are retained for rollback. The source hashes and exact
local command results below bind this record to `SOURCE_COMMIT`; this record
must not be read as clean-client, runtime or production proof.
`SOURCE_COMMIT` anchors the source bytes evaluated by the hashes below; it need
not be the commit that contains this report.

## Final verification record

```text
BASELINE_COMMIT: 44f6e27f0492d7a3cc03cfe812bbe30cdd54bd25
SOURCE_COMMIT: 2fae7117862aba759d001237b9fc1b230efbd9ad
CURRENT_BINDING: docs/evals/portfolio-autoimprove-2026-08-29.md
ULTRA_SHA256: 65f54bcb254ade94e759ed12f069602d62ecc03b4540e7d7d9d5a06152e7a909
REVIEW_SHA256: ed7d3016fc6b988a2d8af77db285e6cfca9b756d46ba521c2714ca7d4bbc7b3e
AUTOIMPROVE_SHA256: 29f0b796a08040a91297d8230876cda128b3a86f0bef9cd4a360a12fda7cdb38
BOOTSTRAP_SHA256: a9424ae6ebcdefeedf83b04a7869173f032f343cd7d4ca8956767633d0385cd2
DETERMINISTIC_SUITE: python3 -B -m unittest discover -s tests -v: 90/90 PASS
QUICK_VALIDATE: skill-creator quick_validate.py on all active skills: 15/15 PASS
SECRET_SCAN: gitleaks dir . --config .gitleaks.toml --redact --no-banner --ignore-gitleaks-allow: PASS
INDEPENDENT_REVIEW: CLEAN; fresh read-only complete-diff review with prediction and name/path evidence
CLIENT_RUNTIME: NOT_VERIFIED
ROLLBACK: restore baseline commit 44f6e27f0492d7a3cc03cfe812bbe30cdd54bd25 or the exact pre-change files
```

If any final gate fails, change the applicable result to `REVERTED` or
`BLOCKED`, retain the failing evidence and do not call the package improved.
