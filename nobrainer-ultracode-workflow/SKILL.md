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

## Model policy (hard rule)

| role | model | why |
|------|-------|-----|
| **orchestration / main loop** | `fable` | planning, decisions, synthesis — where Fable adds the most value |
| **agents (default)** | `opus` | 90% of the fan-out; cheaper than Fable, still strong |
| **agents, trivial only** | `sonnet` | only when a stage is mechanical (rename/format/list/grep/count) and you're sure it suffices |
| **agents** | ~~`fable`~~ | **never** — that's the whole point; Fable stays at the helm |
| ~~`haiku`~~ | only on explicit user request | not by default |

Principle: **Fable steers, Opus executes, Sonnet does the trivial grunt work.** If you have a better idea (a stage really is trivial) drop it to Sonnet and `log(...)` that choice — never silently.

## Step 1 — steer with Fable (main loop)

The main-loop model is the session model; you can't change it mid-session. For the orchestration to run on Fable + the Fable system prompt, start the session via the **claude-fable** launcher:

```bash
claude-fable --model fable          # main loop = Fable model + leaked Fable 5 system prompt
```

If you're already in such a session, proceed. If not, either ask the user to start it as above, or continue knowing the current model is steering (you still control every agent's model per-agent below).

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

// every agent gets FABLE + task, and an EXPLICIT model
const fa = (task, opts = {}) => agent(`${FABLE}\n\n---\n\n${task}`, { model: 'opus', ...opts })

// model per stage: opus by default, sonnet only when genuinely trivial
const UNITS = args?.units ?? [/* work-list — scout it inline before launching the workflow */]

const results = await pipeline(
  UNITS,
  u => fa(`Fan-out slice: ${JSON.stringify(u)}. <what to do>`, { label: `work:${u.id ?? ''}`, phase: 'Fan-out' }),
  (r, u) => fa(`Adversarially verify this result against the real source: ${JSON.stringify(r)}`,
              { model: 'opus', label: `verify:${u.id ?? ''}`, phase: 'Verify' })
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
