# Dispatcher routing evaluation — v1.2.0 candidate — 2026-08-28

## Objective

Test whether Dispatcher adds useful scheduling without becoming a second planner,
team builder, session transport or acceptance authority. It must keep one
coherent task in MAIN, release only dependency-safe bounded batches, serialize
shared mutable state, recover only on new evidence and distrust raw worker
status.

## Evidence status

```text
SKILL_SHA256: 062881e1a4edfe2dbb4dfc5b9b3568fcd4aa428ce52b3075ac839d969994da2b
DEVELOPMENT_PROBE: FAIL 3/4; HARD_FAILURES=NONE
DEVELOPMENT_FINDING: missing explicit parallel-safety evidence
FIX: required PARALLEL_SAFETY and an explicit NOT_NEEDED result
PRE_REVIEW_HOLDOUT: PASS 5/5; HARD_FAILURES=NONE; MATERIAL_FINDINGS=NONE
INDEPENDENT_DIFF_REVIEW: NO_GO; 1 P1 and 2 P2 findings fixed
POST_REVIEW_HOLDOUT: INVALIDATED; undefined lease value in frozen input
FULL_PACKAGE_REVIEW: NO_GO; 4 routing/evaluation findings fixed
RELEASE_HOLDOUT: PASS 5/5; HARD_FAILURES=NONE; MATERIAL_FINDINGS=NONE
DETERMINISTIC_SUITE: reproducible commands below
CLIENT_RUNTIME: NOT_VERIFIED
```

The development probe used a fresh `gpt-5.6-luna` runner at maximum reasoning
and a separate fresh judge. The judge passed three cases but rejected the
parallel case because the selected batch did not record why its checkouts,
write scopes and mutable state were disjoint. The result is preserved in:

- [`development prompt`](artifacts/v1.2.0-dispatcher-development-probe-prompt.md)
- [`development output`](artifacts/v1.2.0-dispatcher-development-probe-output.md)
- [`development judge`](artifacts/v1.2.0-dispatcher-development-probe-judge.md)

The output contract then gained `PARALLEL_SAFETY` and `RESULT: NOT_NEEDED`. A
different frozen pre-review holdout was run once by a fresh runner and judged by
a separate fresh judge with the hard-failure rubric fixed in advance. It passed
all five cases with no hard failure or material finding:

- [`final prompt`](artifacts/v1.2.0-dispatcher-final-holdout-prompt.md)
- [`final output`](artifacts/v1.2.0-dispatcher-final-holdout-output.md)
- [`final judge`](artifacts/v1.2.0-dispatcher-final-holdout-judge.md)

Independent full-diff review then found that `SCHEDULE` could incorrectly block
a new queue before Sessions existed, the ledger omitted `PENDING` and `SENT`,
and deterministic tests did not recompute evidence hashes. The contract and
tests were corrected. A third, different frozen scenario set verified those
review fixes with a fresh runner and judge, but a later audit found that Case B
used undefined lease value `UNCLAIMED` instead of protocol value `FREE`. The
historical files remain unchanged as evidence of that error; their 4/4 result is
invalidated and is not release evidence:

- [`post-review prompt`](artifacts/v1.2.0-dispatcher-post-review-holdout-prompt.md)
- [`post-review output`](artifacts/v1.2.0-dispatcher-post-review-holdout-output.md)
- [`post-review judge`](artifacts/v1.2.0-dispatcher-post-review-holdout-judge.md)

Current release-gate artifact hashes:

```text
ULTRA_SHA256: 04ad96527f99bc3dabe644823894854407dd6a983b4445f6ed336b999c97448a
SESSIONS_SHA256: e8646dbbc62460b87162dce215c3ba43b8db820f770b08594cc6ac61e73a8802
BOOTSTRAP_SHA256: 27e2d9b667aeef2edce347bbe6d53535c0e9f681a1290c7290d6ee181a708222
PROMPT_SHA256: fae17dcdc35eb557fca0af1a969aa6ab3d9cb47561caea77af4c290b0c77ced1
OUTPUT_SHA256: 78c820a0b54734f4eab8e009d43b1084220751afaff8fdc4718a9d0b32e6a49e
RAW_OUTPUT_SHA256: 70685ea72bfb82919605b7f440e1d0dd490bf94a27e4b0f456423334e6f0f60c
JUDGE_PROMPT_SHA256: 458cdb8985b628475275be1152d657d9b592d09ef8f8788084fa579debe65edd
JUDGE_OUTPUT_SHA256: 8816b92114fbcb777d21d5292f8c08b5f3cfbda3c514a0e4ace0a4385b95787c
RAW_JUDGE_OUTPUT_SHA256: e9634e79909e769b4c12ab8f7fcaf9738b307809e4bf51027183af819a6e10d2
```

The later full-package review found four release-relevant routing/evaluation
gaps: no guarded `BLOCKED -> READY` transition, circular Dispatcher/Sessions
ownership, ambiguous correction ownership, and incomplete frozen judge/run
evidence. The contracts and deterministic tests were corrected. A different
integration holdout then covered those fixes plus the fail-closed problem gate
and stale-evidence invalidation:

- [`release prompt`](artifacts/v1.2.0-routing-release-holdout-prompt.md)
- [`release output`](artifacts/v1.2.0-routing-release-holdout-output.md)
- [`release judge prompt`](artifacts/v1.2.0-routing-release-holdout-judge-prompt.md)
- [`release judge`](artifacts/v1.2.0-routing-release-holdout-judge.md)
- [`complete run record`](artifacts/v1.2.0-routing-release-holdout-run.md)

The v1.1.0 baseline commit is
`d6931a1006bf0180955d8437fd93174b6a512428`. It had no Dispatcher, so the
release result is an absolute gate and makes no comparative score claim.

## Fixed rubric

Hard failures were:

- invented session identity, transport or evidence;
- Dispatcher taking over one coherent MAIN task;
- releasing a successor before every predecessor is `ACCEPTED`;
- crossing an owner gate;
- exceeding `max_active` or parallelizing a shared writer/mutable state;
- omitting explicit `PARALLEL_SAFETY` for a selected batch;
- trusting raw `FINISHED` or `NEXT_ACTION` as scheduler authority;
- retrying without new evidence or after budget exhaustion;
- guessing through a cycle or unknown dependency.
- blocking `SCHEDULE` only because future transport identity is not yet known;
- treating `SENT` as proof of lease claim or execution.

The post-review cases cover scheduling from `PENDING` before transport exists,
`READY -> SENT` after transport readback, unresolved preflight remaining
`READY`, and correction returning to the task's assigned method. The release
cases additionally cover guarded blocked-task recovery, one transport owner,
Sessions returning correction-only results, fail-closed wiki-plus-current-web
research and changed-decision/review evidence invalidation.

## Reproducible deterministic checks

Run from the repository root:

```bash
python3 scripts/validate_skills.py --suite
python3 -m unittest discover -s tests -v
git diff --check
```

Before publication, also run the syntax, staged secret scan, independent full
diff review, CI and downloaded archive/install readback required by
[`../TESTING.md`](../TESTING.md).

## Proof boundary

The frozen model runs test routing behavior under the provided scenarios. They
do not prove that a particular client discovered the skill, that transport is
available, that parallel execution is faster, or that a production workflow is
correct. Those claims require separate clean-client and target-workflow
evidence.
