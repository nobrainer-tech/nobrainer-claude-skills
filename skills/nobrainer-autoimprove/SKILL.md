---
name: nobrainer-autoimprove
description: "Use when the owner says nb-autoimprove, deep-autoresearch, code-autoresearch, nobrainer-capture-lesson, or nobrainer-continuous-improvement; asks to improve a skill or prompt; or wants a measurable bounded baseline-variant-evaluation loop instead of one subjective rewrite."
---

# NoBrainer Autoimprove

Improve one artifact only when a frozen evaluation proves the change is better.
This skill is explicitly inspired by Andrej Karpathy's
[autoresearch](https://github.com/karpathy/autoresearch) experiment loop and
adapts its measure-change-keep-or-revert idea to skills, prompts, instructions,
checklists and other reviewable artifacts. It is an independent adaptation, not
an official Karpathy project.

## When not to loop

Fix an obvious typo, dead link or deterministic defect directly. Use the
project's normal test-driven workflow for code with a strong existing harness.
Do not start when success cannot be measured, the target cannot be isolated, or
the proposed mutation touches credentials, production, safety controls,
external publishing or irreversible data without an owner-approved experiment.

## From feedback to durable improvement

Treat an owner correction as evidence, not automatic permission to rewrite the
system. Classify it first:

- a task-local clarification changes only the current task;
- an explicit durable preference, decision or verified fact may be captured
  through `nobrainer-wiki` mode `ADD` only when its scope, confidentiality and
  configured `LEARNING_WRITE_POLICY` permit it;
- a repeatable behavior gap becomes a regression scenario for this skill;
- a deterministic defect is fixed directly and covered by a test.

When `AGENT_ERROR_CORRECTED` is raised by `nobrainer-ultra`, preserve the exact
failing scenario and error fingerprint before editing. Correct the active task
first. Then classify the smallest reusable prevention candidate and honor the
project's configured policy before any durable learning write:

- `AUTO_SCOPED`: promote at most one minimal, sourced rule to its one canonical
  governed project-local store;
- `ASK`: prepare one exact single-store diff and request the persistence
  decision without applying it;
- `OFF`: keep the candidate task-local and do not create a durable diff or
  modify `AGENTS.md`, `tasks/lessons.md` or a wiki.

Use this experiment when behavior needs generalization beyond the deterministic
active-task correction. The experiment's own target and write scope still need
the normal authorization; learning policy does not grant an unrelated edit.

For a behavior change, preserve the failing example, define the expected
response, and run the bounded experiment below. One anecdote does not justify a
broad inferred user trait or a global instruction rewrite. Record what was
learned, its source, scope and rollback so personalization remains visible and
correctable.

## Experiment contract

Freeze before changing the target:

```text
TARGET: <one artifact and allowed write scope>
OBJECTIVE: <one observable improvement>
BASELINE_VERSION: <commit/hash/copy>
DEVELOPMENT_EVAL: <representative cases used to iterate>
HOLDOUT_EVAL: <unseen cases used only for promotion>
HARD_GATES: <format, safety, forbidden values, links, deterministic tests>
SCORE: <criteria, weights, aggregation, direction>
BUDGET: <rounds, variants, time/tokens/cost>
PLATEAU: <minimum meaningful delta and dry rounds>
ROLLBACK: <restore procedure and readback>
OWNER_GATES: <actions not authorized by the loop>
```

Preserve the original target and run in an isolated copy, branch or worktree.
One coordinator owns the champion and log; generators must not race on the same
file.

For production code, freeze the harness and metric before the first candidate.
Prefer one behavioral change per round, preserve a control/baseline path, and
record the exact commit, test data and environment so a gain can be reproduced.
The loop may optimize code only inside an approved branch and write scope; it
does not deploy, tune on production feedback silently or weaken protected tests.

## Build a trustworthy eval

Use deterministic checks wherever possible. For subjective quality define a
concrete rubric whose criteria map to the target workflow. For a skill this
usually includes trigger precision, actionability, correctness, failure/stop
coverage, compatibility and concision.

Freeze two scenario sets:

- development cases exercise common, edge, adversarial and non-trigger inputs;
- holdout cases detect overfitting and are not shown to generators or used to
  select an iteration.

Score the unchanged baseline on development only. Evaluate the sealed baseline
and selected champion against holdout cases together, exactly once, during
`FINAL_HOLDOUT`. Do not reveal holdout cases, criterion results or failure clues
to generators before that check. If the champion fails, create a new holdout,
re-baseline and start a new bounded experiment instead of tuning against the
failed holdout. If a rubric, weights or cases change, invalidate prior scores
and re-baseline. Never tune against one anecdote and call the artifact generally
improved.

For LLM judgment use independent judges, anonymized/shuffled candidates,
per-criterion reasons, median aggregation and pairwise tie-breaks. Judges do not
generate candidates and do not know which candidate is incumbent. Record model
or capability substitutions because judge drift affects comparability.

## Bounded loop

```text
FRAME -> BASELINE -> GENERATE -> HARD_GATE -> DEV_SCORE -> SELECT -> GRAFT
      -> REPEAT_OR_STOP -> FINAL_HOLDOUT -> PROMOTE_OR_REVERT
```

### Generate

Produce three to six complete candidates with different hypotheses, not
paraphrases. Useful strategies include restructure, compress, expand missing
failure coverage, sharpen routing, add a concrete example, remove duplication,
or invert the flow around stop conditions.

### Hard gate and score

Run format, security, public-clean, deterministic tests and repository-specific
validators before spending judge budget. A hard-gate failure is disqualified,
not averaged away.

Score surviving candidates on the unchanged development eval. Select the best
median score only when it exceeds the current champion beyond expected judge
noise. On a near-tie prefer the simpler, shorter, lower-risk candidate.

### Graft

Inspect criterion vectors. A losing candidate may contain the strongest trigger
or rollback section. Build one challenger that grafts only those distinct
strengths onto the champion, then rerun all gates and scoring. Keep it only when
it wins.

### Holdout and promotion

After development iteration has stopped, run the final champion and original
baseline once on the untouched frozen holdout. Do not use that result to tune
another candidate in the same experiment.
Promotion requires:

- all hard gates pass;
- meaningful improvement on the primary score;
- no unacceptable regression in a protected criterion or scenario;
- target-workflow review when quality is subjective;
- scoped diff, retained baseline and tested rollback.

A development gain that disappears on holdout is overfitting. Revert to the
previous champion and record the negative result. Any further tuning requires a
new holdout, a new baseline and a new experiment record.

Prefer the smallest promoted change. Continuous improvement beats delayed
perfection only when each increment passes its current acceptance gates; the
principle never converts known failure or missing proof into success.

## Stop conditions

Stop on the first of:

- minimum meaningful improvement is not reached for the configured dry rounds;
- score reaches a practical ceiling without protected regressions;
- experiment budget is exhausted;
- candidates converge on the same shape;
- hard gate regresses during development;
- final holdout regresses, which ends promotion rather than starting a new
  iteration;
- target, constraints, frozen eval or owner authorization changes.

Do not continue indefinitely. A null result is valid: retain the baseline and
report that no candidate proved better.

## Round log

```text
ROUND: <integer>
CHAMPION_IN: <version and development score>
CANDIDATES: <strategy, hard-gate result, criterion vector, score>
WINNER: <candidate or NONE>
GRAFT: <source ideas and result or NONE>
CHAMPION_OUT: <version and delta>
REGRESSIONS: <protected criteria/cases or NONE>
JUDGE_AGREEMENT: <dispersion and tie-break>
STOP_CHECK: <continue or exact condition>
```

## Final report

Return the winning artifact, baseline-to-final development and holdout scores,
hard-gate/test output, full compact round log, protected regressions, budget
used, stop reason, diff, rollback and remaining uncertainty. Do not claim
"improved" without paired scores on the same frozen eval and successful holdout
promotion.
