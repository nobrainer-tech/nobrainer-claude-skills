# Dispatcher routing evaluation — v1.2.0 candidate — 2026-08-28

## Objective

Test whether Dispatcher adds useful scheduling without becoming a second planner,
team builder, session transport or acceptance authority. It must keep one
coherent task in MAIN, release only dependency-safe bounded batches, serialize
shared mutable state, recover only on new evidence and distrust raw worker
status.

## Evidence status

```text
SKILL_SHA256: 03311d61861aee8ee5dd92c3a6bb8bddc6a8a7098117cd2fca9328641a7f6b54
DEVELOPMENT_PROBE: FAIL 3/4; HARD_FAILURES=NONE
DEVELOPMENT_FINDING: missing explicit parallel-safety evidence
FIX: required PARALLEL_SAFETY and an explicit NOT_NEEDED result
PRE_REVIEW_HOLDOUT: PASS 5/5; HARD_FAILURES=NONE; MATERIAL_FINDINGS=NONE
INDEPENDENT_DIFF_REVIEW: NO_GO; 1 P1 and 2 P2 findings fixed
POST_REVIEW_HOLDOUT: PASS 4/4; HARD_FAILURES=NONE; MATERIAL_FINDINGS=NONE
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
review fixes with a fresh runner and judge:

- [`post-review prompt`](artifacts/v1.2.0-dispatcher-post-review-holdout-prompt.md)
- [`post-review output`](artifacts/v1.2.0-dispatcher-post-review-holdout-output.md)
- [`post-review judge`](artifacts/v1.2.0-dispatcher-post-review-holdout-judge.md)

Current release-gate artifact hashes:

```text
PROMPT_SHA256: 501362756c79c97c46b69f5211d9d640b1c3592af0a079c1b9b43a42e01ff9a2
OUTPUT_SHA256: af274d8abd57f76fc4538b0e56e8e68c859592e988b0ebcca263578be9c1caef
JUDGE_SHA256: 0f300292f48977b1e821907a3add8cd1dab11985e0d25ed7288252aad3369452
```

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
`READY`, and correction returning to the task's assigned method.

## Reproducible deterministic checks

Run from the repository root:

```bash
python3 scripts/validate_skills.py --suite
python3 -m unittest discover -s tests -v
python3 /path/to/skill-creator/scripts/quick_validate.py skills/nobrainer-dispatcher
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
