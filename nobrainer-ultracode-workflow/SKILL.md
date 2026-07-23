---
name: nobrainer-ultracode-workflow
description: Run an "ultracode" multi-agent Workflow with cost discipline — orchestration steered by Fable (main loop), subagents on Opus by default to save tokens (Sonnet only for genuinely trivial stages), every agent carrying a compact Fable directive so they behave like Fable without paying Fable's price. Use when the user says "ultracode workflow", "fable-steered workflow", "fan out with fable", or asks for a big multi-agent job (audit / review / migration / research / broad sweep) that should be Fable-quality but cost-disciplined. Pairs with the claude-fable skill.
---

# nobrainer-ultracode-workflow — ultracode, Fable-steered, Opus agents

A pattern for running large multi-agent jobs (the `Workflow` tool) so that **Fable's quality stays at the helm** while you **don't pay Fable's price for every agent**.

Pairs with the **claude-fable** skill (which applies the leaked Fable 5 system prompt to the session).

## When to use
- A genuinely multi-agent job: audit, code review, migration, research, broad sweep, "be exhaustive".
- You want Fable's brain on planning/synthesis, but the fan-out to be cheap.
- Triggers: "ultracode workflow", "fable-steered workflow", "fan out with fable, opus agents".

Do **not** use for trivial, single-file edits — do those directly. A multi-agent workflow for one file just burns tokens.

## Model tiers — and how to choose

There is no single fixed model assignment. There are **three tiers**; this skill helps you choose. The orchestrator = the session model (set at launch, Step 1); agents and verify are set per-tier in the script.

| tier | orchestrator (session) | agents | verify | when |
|------|------------------------|--------|--------|------|
| **premium** | `fable` | `opus` | `opus` | hard/creative slices, high stakes |
| **standard** _(default)_ | `opus` | `sonnet` | `opus` | decomposable, verifiable slices |
| **budget** | `opus`/`sonnet` | `sonnet` | `sonnet` | bulk sweep, mechanical |

Leverage principle: **the orchestrator has more leverage than the agents** — one decomposition/synthesis/judgment decision shapes the whole run. So dropping the agents (Opus→Sonnet) hurts less than dropping the orchestrator (Fable→Opus). `fable` on agents — never; `haiku` — only on explicit request.

### How to choose a tier
Start at **standard**. Then:
- **→ premium** if ANY: a slice needs deep reasoning (bugs, security, design/architecture), high stakes (production/irreversible), creative synthesis, or ambiguous/underspecified slices.
- **→ budget** only if ALL: slices are mechanical and well-specified (rename/format/extract/sweep), each independently verifiable, low stakes, large volume.
- **unsure between two** → calibrate (below), don't guess.

Quick heuristic: bug-hunt/security/design → premium · review/sweep/migration/research → standard · bulk mechanical → budget.

### Calibrate — measure, don't guess
For a new task class: take **one representative slice**, run it on both candidate tiers, score both outputs against the same rubric (blind judge panel — use `karpathy-auto-improver`). Stay on the cheaper tier if Δ is within judge noise (~<0.3/10). One calibration per task class, then reuse. A cheap agent's miss is still caught by the verify stage — so keep verify one notch above the agents.

## Step 1 — orchestrator = the session model (per tier)

The main-loop model is the session model; you can't change it mid-session. Set it to match your chosen tier:

```bash
# premium: orchestrator = Fable + Fable system prompt
claude-fable --model fable
# standard / budget: orchestrator = Opus — a plain opus session,
#   or `claude-fable --model opus` if you want the Fable prompt at the helm more cheaply
```

If you're already in the right session, proceed. If not, either ask the user to launch as above, or continue knowing the current model is steering (you still set the agents per-tier in the script below).

## Step 2 — Fable on the agents without burning tokens

The full Fable prompt (shipped by the **claude-fable** skill as `CLAUDE-CODE-FABLE-5.md`) is **~24k tokens**. Injecting it into each of N agents is a cost disaster and defeats the purpose of this skill.

So **by default** inject a **condensed Fable directive** (below, ~10 lines) as a preamble to each agent's prompt. That gives Fable-like behavior (raw output, decisiveness, verification, root-cause) for a few hundred tokens instead of 24k.

The full prompt on agents — **only on explicit request** ("full fable on agents" / "full fidelity"): build an agentType (e.g. `fable-agent`) whose system prompt is that file and pass `agentType:'fable-agent'` — and warn about the cost.

Condensed directive (copy into the script as `const FABLE`):

```
Operate as Claude Fable 5 (Mythos-tier) on a scoped slice of a Fable-orchestrated task.
- Your final text IS the result: return raw data/artifacts, not chat. No preamble, no summary padding, no emoji.
- You are a subagent — act decisively on what the task gives you; never ask for confirmation.
- Verify before claiming done: trace the real code/values/output. Never assert "should work".
- Root cause over symptom. One correct approach, fully executed — no "…rest unchanged", no half-answers.
- Be precise and terse; lead with the outcome.
- Flag uncertainty explicitly instead of guessing; if evidence contradicts the premise, say so.
```

## Step 3 — Workflow pattern (copy and adapt)

```js
export const meta = {
  name: 'ultracode-run',
  description: 'Fable-steered fan-out, Opus agents (Sonnet for trivial), compact Fable directive',
  phases: [{ title: 'Fan-out' }, { title: 'Verify' }],
}

// --- Fable directive injected into every agent (cheap) ---
const FABLE = `Operate as Claude Fable 5 (Mythos-tier) on a scoped slice of a Fable-orchestrated task.
- Your final text IS the result: return raw data/artifacts, not chat. No preamble, no emoji.
- You are a subagent — act decisively; never ask for confirmation.
- Verify before claiming done: trace the real code/values/output. Never assert "should work".
- Root cause over symptom. One correct approach, fully executed — no "…rest unchanged".
- Lead with the outcome, be terse. Flag uncertainty; if evidence contradicts the premise, say so.`

// tier -> agent/verify models (orchestrator = session model, Step 1)
const TIER = args?.tier ?? 'standard'
const T = ({ premium:{agent:'opus',verify:'opus'}, standard:{agent:'sonnet',verify:'opus'}, budget:{agent:'sonnet',verify:'sonnet'} })[TIER]

// every agent gets FABLE (quality directive) + task, model from the tier
const fa = (task, opts = {}) => agent(`${FABLE}\n\n---\n\n${task}`, { model: T.agent, ...opts })

const UNITS = args?.units ?? [/* work-list — scout it inline before launching the workflow */]

const results = await pipeline(
  UNITS,
  u => fa(`Fan-out slice: ${JSON.stringify(u)}. <what to do>`, { label: `work:${u.id ?? ''}`, phase: 'Fan-out' }),
  (r, u) => fa(`Adversarially verify this result against the real source: ${JSON.stringify(r)}`,
              { model: T.verify, label: `verify:${u.id ?? ''}`, phase: 'Verify' })
)

// example trivial stage (rename/format/count) → sonnet:
// const tidy = await parallel(FILES.map(f => () => fa(`Normalize headers in ${f}`, {model:'sonnet', phase:'Fan-out'})))

return results.filter(Boolean)
```

Same rules as the `Workflow` tool: `pipeline` by default, `parallel` only for a real barrier; `.filter(Boolean)` after fan-out; the script has no filesystem access — if you want the full Fable prompt on agents, read it in the main loop and paste it into a `const`, not inside the script.

## Scaling to the task
- "find bugs / quick check" → a few Opus agents, single-vote verify.
- "thorough audit / be exhaustive" → larger Opus pool + 3–5-vote adversarial verify + a synthesis stage (synthesis can run on the main loop = Fable).
- Purely mechanical stages in the middle → Sonnet, logged.

## Why this shape (cost)
Fable (Mythos-tier) is the priciest. Keeping Fable only at the helm (planning + synthesis, where quality decides the outcome) and pushing the volume fan-out to Opus/Sonnet gives you Fable-quality decisions at a fraction of "everything on Fable". The condensed directive gives agents Fable-like behavior without a 24k-token prompt each.

## Verify before "done"
- The main loop (Fable) reads agent results and does not trust "passed" without evidence.
- If the workflow capped coverage (top-N, no retry) — `log(...)` what was dropped.
