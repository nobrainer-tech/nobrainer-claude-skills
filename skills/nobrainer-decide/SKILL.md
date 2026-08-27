---
name: nobrainer-decide
description: "Use when the owner says nb-decide, asks what to choose, or needs a consequential technical, product, vendor, workflow, or investment-of-time decision with competing options, uncertainty, lock-in, or meaningful downside."
---

# NoBrainer Decide

Deliver one ranked decision with evidence, confidence, watchpoints and kill
criteria. Do not hide behind several flavors of "it depends". This skill decides;
it does not diagnose an unknown failure or execute the chosen option.

Use `nobrainer-rca` first when the unresolved question is causal. Use official
Superpowers brainstorming when the option space itself needs product discovery.

## Calibrate rigor

Do not run a panel for a factual lookup, an already-made choice, or an obvious
reversible edit.

- `LIGHT`: one explicit pass for reversible, low-cost choices with clear facts.
- `STANDARD`: at least three independent perspectives for meaningful tradeoffs:
  option generation, scoring, and blind attack/cold review.
- `HIGH`: at least six bounded independent runs for architecture, material cost,
  difficult rollback, public commitments, safety, or long lock-in. Separate two
  option generators, scorer, blind attacker, cold reviewer, and synthesizer.

Use fresh or deliberately bounded contexts. Independence means different
evidence/roles and no inherited rationale, not merely several calls to the same
prompt. When independent execution is unavailable, mark the analysis partial;
do not claim a panel. Never hardcode a provider or model family into the
protocol; select the strongest available capability appropriate to each role.

## 1. Frame the actual decision

Restate:

- decision, owner, deadline and observable outcome;
- baseline/status quo and what happens if nothing changes;
- hard constraints, reversible vs irreversible effects, and owner gates;
- evidence freshness and consequential unknowns.

Rewrite the problem once without project nouns. Ask "what system property makes
this decision necessary?" until symptom and root cause are separated. If a
candidate appears immediately, record it as an anchor to challenge, not the
answer.

Ask at most one focused clarification round. Then either decide or identify the
single missing owner choice/evidence that truly blocks a decision.

## 2. Generate different shapes

Produce at least three mechanisms, not parameter variants. Always include the
status quo. Include at least one shape from outside the user's initial frame:

- measure first;
- fix the systemic cause;
- remove the requirement;
- accept and observe within an explicit budget.

For every option state mechanism, expected benefit, key dependency, worst
failure, reversibility and earliest useful evidence. Reject duplicate shapes.

## 3. Score transparently

Define criteria from the actual outcome before scoring. The default ledger is:

| Criterion | Default weight |
|---|---:|
| outcome/metric movement | 3 |
| correctness and evidence | 3 |
| optionality and lock-in | 3 |
| downside/antifragility | 3 |
| production or operational readiness | 2 |
| recurring cost and attention tax | 2 |
| quality/best-in-class fit | 2 |
| reversibility | 1 |
| one-time cost | 1 |
| time to useful result | 1 |

Change weights only with an explicit reason. Score 1–5 and show weighted totals,
source quality, sensitivity to uncertain assumptions, one-time and recurring
cost. Numbers do not auto-select the winner; they expose the tradeoff.

Antifragility means bounded downside, useful feedback under stress, preserved
options, redundancy where failure matters, and asymmetric upside. A fragile
option hides tail risk, single points of failure, or an expensive exit.

## 4. Attack the leader

A blind attacker receives the problem, evidence and leading option but not the
scorer's rationale. It must answer:

1. What if the problem framing is wrong?
2. Which rejected option deserves the strongest steelman?
3. Is the leader winning because it is familiar or easy?
4. Which assumption can reverse the ranking?
5. Is this systemic, a fallback, or a workaround?

Re-score when an attack changes a criterion or assumption. A fallback may win,
but name the systemic alternative and the trigger for revisiting it.

## 5. Cold review and commitment

A fresh reviewer sees the original decision, evidence and options, not prior
reasoning. It checks missing shapes, stale evidence, score sensitivity,
operational burden, rollback and owner gates. The synthesizer reconciles both
attacks and selects exactly one option.

Do not turn a recommendation into execution authority. Publishing, spending,
merging, deployment, credentials, production mutation, destructive action, and
safety changes remain explicit owner gates.

## Decision record

```text
DECISION
  Choice: <one option>
  Confidence: LOW | MEDIUM | HIGH - <reason>
  Why it beats #2: <one evidence-bound sentence>
  Type: SYSTEMIC | FALLBACK | WORKAROUND
  Rigor: LIGHT | STANDARD | HIGH

SCORECARD
  <criteria, weights, scores, totals, sensitivity>

WATCHPOINTS
  - <metric + threshold + review/action>
  - <metric + threshold + review/action>

KILL_CRITERIA
  - If <observable condition> by <time/event>, stop or revert to <option>.

ROLLBACK
  - <procedure, owner, and readback>

REJECTED_OPTIONS
  - <option>: <decisive reason and revisit trigger>

OPEN_ASSUMPTIONS
  - <at most two genuinely decision-relevant assumptions or NONE>

OWNER_GATE
  - <exact approval needed before action or NONE>
```

End with one next action. Preserve the decision and evidence in the project's
existing durable record only when it will guide future work; do not create a
second source of truth.
