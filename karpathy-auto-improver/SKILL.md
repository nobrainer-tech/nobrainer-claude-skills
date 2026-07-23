---
name: karpathy-auto-improver
description: >-
  A Karpathy-style autonomous improvement loop that iteratively improves a
  target artifact — a SKILL.md, a prompt, a checklist, a rubric, a config, or
  any deliverable judged by a metric — through scored rounds. Applies the
  "autoresearch" pattern (define score, baseline, fan out diverse variants,
  judge, keep the winner, graft best ideas, repeat until plateau) to
  self-improvement. Use when the user says "auto improve", "autoresearch",
  "improve this skill", "karpathy loop", "score and iterate", "make this
  better and prove it", or wants an artifact optimized against a measurable
  objective rather than hand-tweaked once.
---

# Karpathy Auto-Improver

An autonomous, score-driven loop for making a target artifact measurably better.
The premise (from Andrej Karpathy's framing of iterative optimization): **you
cannot improve what you do not measure, and you have not improved anything until
the number moves on a real eval.** Every claim of "better" must be backed by a
score produced by a defined evaluation, not by vibes.

This skill applies that discipline to *soft* artifacts — prompts, skills,
checklists, instructions, policies — where the "eval" is often an LLM-judge
panel plus a few deterministic checks, rather than a unit-test suite.

## When to use

- Optimizing a `SKILL.md`, system prompt, or instruction set that behaves
  inconsistently or underperforms.
- Tightening a checklist, rubric, or policy document against measurable criteria.
- Any task shaped like: "here is an artifact + a notion of good — make it better
  and show me it's actually better."

## When NOT to use

- One-line obvious fixes (typos, a broken link). Just fix it.
- Tasks with no definable success metric. If you can't write the rubric, stop
  and get one before looping — an unmeasured loop is theater.
- Hard code with an existing deterministic test harness — a code-specific
  autoresearch loop is a better fit there.

## The non-negotiables

1. **Define the score before touching the artifact.** No rubric, no loop.
2. **Baseline first.** Score the current artifact unchanged. That number is the
   bar every variant must beat.
3. **Never claim a gain without the score.** "This reads better" is not a result.
   "Baseline 6.4 → v3 7.8 on the same eval, n=8 cases" is a result.
4. **Log every round.** What was tried, what it scored, why it won or lost.
   The log is the deliverable's audit trail.
5. **Same eval, every round.** If you change the rubric or the test cases
   mid-run, all prior scores are void — re-baseline.
6. **Keep the winner, cannibalize the losers.** Runners-up usually contain one
   good idea; graft it, don't discard it.

---

## The Core Loop

```
0. FRAME    → identify target artifact, objective, and constraints
1. RUBRIC   → define a measurable score + a repeatable eval (test cases + judge)
2. BASELINE → score the current artifact as-is; record it
3. GENERATE → produce N diverse variants (different strategies, not paraphrases)
4. SCORE    → run each variant through the SAME eval; record all scores
5. SELECT   → keep the top scorer as the new champion
6. GRAFT    → merge the best distinct ideas from runners-up into a challenger,
              score it, keep it only if it beats the champion
7. LOOP     → back to 3 with the champion as the new baseline
8. STOP     → when score plateaus OR K dry rounds OR budget hit; emit best + log
```

### Step 0 — Frame

Write, in three lines:
- **Target:** the exact file/artifact being improved.
- **Objective:** what "better" means in one sentence (e.g. "a skill that a
  fresh agent can follow to correctly do X without asking clarifying questions").
- **Constraints:** hard limits (length cap, must stay public-clean, must keep
  YAML frontmatter valid, no new dependencies).

### Step 1 — Rubric + Eval

The heart of the method. Build two things:

**A. A scoring rubric** — weighted, concrete criteria, each scored on a fixed
scale (0–10 or 0–5). Example for a SKILL.md:

| Criterion | Weight | What a 10 looks like |
|---|---|---|
| Trigger clarity | 0.20 | Description fires on the right requests, not others |
| Actionability | 0.30 | An agent can execute steps with zero guesswork |
| Correctness | 0.25 | Instructions are technically right; no dead ends |
| Completeness | 0.15 | Covers edge cases, failure modes, stop criteria |
| Concision | 0.10 | No filler; every line earns its place |

Weighted score = Σ(criterion × weight). This is the single number you optimize.

**B. A repeatable eval** — the fixed set of inputs the artifact is judged
against. Make it as deterministic as possible:
- **Test cases:** 5–12 concrete scenarios the artifact must handle. For a
  prompt/skill, these are representative tasks; for a checklist, representative
  situations. Freeze this set for the whole run.
- **Deterministic checks** (score these mechanically, no judgment): frontmatter
  parses, length ≤ cap, no forbidden strings, required sections present, links
  resolve. Failing a hard check = automatic disqualification, not a soft penalty.
- **Judge:** for the subjective criteria, use an LLM-judge. To fight judge noise:
  - Use a **panel** (3 judges) and take the median, not a single judge.
  - Give the judge the rubric verbatim and require a per-criterion score with a
    one-line justification each — no bare overall numbers.
  - **Score variants blind:** strip any "this is v3" labels; present anonymized,
    shuffled. Judges must not know which is the incumbent.
  - Where feasible, judge **pairwise** (A vs B, which better and why) in addition
    to absolute scoring — pairwise is more stable than absolute for close calls.

### Step 2 — Baseline

Run the current artifact through the full eval. Record the weighted score and
per-criterion breakdown. This is round 0 in the log. If the baseline already
scores near-ceiling on every criterion, say so and stop — there may be nothing
to win.

### Step 3 — Generate N diverse variants

Diversity is the fuel. Paraphrases waste rounds. Force *strategic* diversity —
each variant pursues a different hypothesis about what's holding the score down:

- **Restructure:** reorder/regroup sections for a different reading flow.
- **Compress:** cut hard for concision — does score hold or improve?
- **Expand:** add the missing edge-case / failure-mode coverage.
- **Sharpen triggers:** rewrite the description/frontmatter for precision.
- **Concretize:** replace abstract instructions with worked examples.
- **Invert:** lead with the stop-criteria / failure modes instead of the happy path.

N = 3–6 is a good default. Each variant should be a *complete* candidate
artifact, not a diff sketch.

### Step 4 — Score each

Every variant goes through the **same** eval from Step 1. Record the weighted
score and per-criterion vector for each. Any variant failing a deterministic
hard check is disqualified before judging (don't spend judge budget on it).

### Step 5 — Select the champion

Highest weighted median score wins and becomes the new champion. On a near-tie
(within judge noise, typically < 0.3 on a 10-scale), prefer the one that is
simpler / shorter / lower-risk — don't chase noise.

### Step 6 — Graft best ideas from runners-up

Inspect the per-criterion vectors. A runner-up that lost overall may have topped
one criterion (e.g. best trigger clarity). Build a **challenger** that grafts
those winning elements onto the champion, then score the challenger on the same
eval. Keep it only if it beats the champion. This is how you climb past any
single variant's ceiling.

### Step 7 — Loop

Champion becomes the new baseline. Return to Step 3. Each round's bar is the
current champion's score, never the original baseline.

### Step 8 — Stop criteria

Stop when **any** of these fire — and state which one:

- **Plateau:** best score improves by less than a threshold (e.g. < 2% relative,
  or < 0.2 absolute on a 10-scale) for a round.
- **K dry rounds:** K consecutive rounds (default K = 2) with no new champion.
- **Ceiling:** champion scores at/near max on all criteria.
- **Budget:** max rounds / token / time budget reached (set it up front).

On stop, emit: the winning artifact, its score vs baseline, and the full round
log. If the best score never beat baseline, **say so honestly** and ship the
original — a loop that found nothing is a valid, reportable outcome.

---

## Running it as a multi-agent Workflow (fan-out + judge panel)

Use this when the artifact is substantial, N is large, or you want parallelism
and judge independence. Roles:

- **Orchestrator** — frames the task, holds the champion, decides stop.
- **Generator agents** (N in parallel) — each owns one diversity strategy from
  Step 3 and returns one complete candidate artifact. Fan them out concurrently;
  they don't share files, so there's no write conflict.
- **Judge panel** (3 in parallel) — each independently scores *all* candidates
  (anonymized, shuffled) against the frozen rubric, returning per-criterion
  scores + justifications. Orchestrator takes the per-criterion median across
  judges.
- **Grafter** — after selection, builds and submits the challenger (Step 6).

Sketch:

```
Round r:
  orchestrator: broadcast {champion, rubric, test_cases, constraints}
  parallel:  gen_1(restructure) ... gen_N(concretize)   -> candidates[]
  deterministic_gate(candidates)                          -> survivors[]
  parallel:  judge_A, judge_B, judge_C  score survivors (blind, shuffled)
  orchestrator: median-aggregate -> champion', log_round(r)
  grafter: build challenger from runner-up strengths -> score -> maybe champion'
  if stop_criteria(): break
```

Key discipline for the multi-agent form:
- Judges must be **separate agents/contexts** from generators, and must not see
  which candidate is the incumbent — otherwise incumbency bias inflates the
  baseline and stalls the loop.
- The orchestrator owns the single source of truth (champion + log). Generators
  and judges are stateless per round.

## Running it lightweight (single-loop, no orchestration)

For small artifacts, do the whole thing in one context — no subagents:

1. Write the rubric + 5 test cases inline.
2. Score the baseline yourself against the rubric (fill the per-criterion table).
3. Generate 3 variants using 3 different strategies.
4. Score all 3 against the same rubric; to reduce your own bias, score each
   criterion across all candidates in one pass (column by column), blind to which
   is the incumbent where you can.
5. Keep the winner; graft the best idea from the other two into a 4th; re-score.
6. Repeat once or twice until it plateaus.
7. Output the winner + a compact round log.

Same rules apply: baseline first, same eval every round, log every round, no
gain claimed without the number.

---

## Round log format

Keep a running log — one block per round. This is mandatory, not optional.

```
## Round 2
champion_in: v1 (weighted 7.1)
variants:
  v2 restructure   → 7.4   [trigger 8, action 7, correct 7, complete 8, concise 7]
  v3 compress      → 6.9   [trigger 7, action 7, correct 7, complete 6, concise 9]
  v4 concretize    → 7.9   [trigger 8, action 9, correct 8, complete 7, concise 6]   ← winner
graft: took v3's concision intro into v4 → v5 → 8.1  ← new champion
champion_out: v5 (weighted 8.1)  Δ +1.0 vs baseline (7.1)
notes: concrete worked-examples drove the actionability jump; compression alone hurt completeness
```

At the end, a summary table: baseline → each champion → final, with the Δ and
which stop criterion fired.

---

## Guardrails

- **Verify against the real eval.** If the eval is supposed to be deterministic,
  actually run the deterministic checks — don't assume they pass. If a check
  can be executed (parse the frontmatter, count the length, resolve links), run
  it; don't eyeball it.
- **No score, no claim.** Never report "improved" without the paired numbers and
  the eval they came from. If you couldn't score it, you didn't improve it.
- **Freeze the eval.** Changing rubric weights or test cases mid-run invalidates
  earlier scores — if you must change them, re-baseline and note the reset.
- **Beware judge drift and self-preference.** Panel + median + blind/shuffled
  presentation + pairwise tie-breaks. A lone judge scoring labeled candidates is
  the classic way to fool yourself.
- **Diversity over volume.** Six paraphrases lose to three genuinely different
  strategies. If variants are converging on the same shape, inject a new strategy.
- **Regression guard.** The champion must beat the *previous* champion on the
  same eval; a variant that improves one criterion while tanking another (and
  dropping the weighted score) does not win.
- **Honest null result.** If nothing beats baseline within budget, ship the
  original and report the negative result plainly. That is a successful run.

## Output of a run

1. The winning artifact (full, ready to use).
2. A one-line result: `baseline X.X → final Y.Y (Δ +Z.Z) on <eval>, <n> cases,
   stopped on <criterion>`.
3. The full round log.
4. If final ≤ baseline: the original artifact, unchanged, plus the negative-result
   note.