---
name: agents-restraint
description: "Install eight engineering rules into a repo's CLAUDE.md and AGENTS.md that stop a coding agent from over-building — no compatibility layers, no speculative abstraction, no reinventing what a dependency already does. Use when the user says 'agents-restraint', 'add the engineering rules', 'stop the agent over-engineering', 'AGENTS.md rules', 'dodaj zasady inzynierskie', or when a repo has no agent instructions and the agent keeps producing more code than the task needs."
---

# Agents Restraint

Eight rules for a repo's agent instructions. They exist to hold a coding agent
back *before* it starts writing.

## Why this is worth the eight lines

The expensive failure mode in AI-written code is not wrong code — it is **too
much** code. Left unconstrained, an agent pulls in three dependencies and five
layers of abstraction for something the standard library does in ten lines. Ask
it to fix that, and it writes two hundred more lines.

Origin: a Vercel Next.js engineer reportedly burned ~60B tokens (a six-figure
dollar amount) iterating on an `AGENTS.md`, and what survived compresses to
these eight rules. Cursor, Claude Code, Codex and Windsurf all read `AGENTS.md`
from the repo root automatically.

## Apply

Insert `assets/block.md` verbatim into **both** `CLAUDE.md` and `AGENTS.md` at
the repo root, creating either if missing.

The block is delimited by `ENG-RULES:START` / `:END`. If those markers are
already present, replace what is between them rather than appending — applying
this twice must not leave two copies.

Append after existing content. Do not reorder or rewrite anything else in those
files. If `AGENTS.md` carries a managed block from another tool (a
`pane-agent-context` section, for instance), leave it exactly as it is.

## Before you paste this into every repo

**Rule 1 is the sharp one.** "Delete what is obsolete, no fallbacks, no
migrations" is right for a web product with a single deploy target. It is
actively dangerous in a service holding state or money — a trading bot on a
five-minute cron, anything mid-migration, anything with external consumers of
its API. In those repos, either drop rule 1 or pair it with a rule that requires
a passing test suite before any removal.

**Check for contradictions rather than stacking.** If the target repo already
carries a rule like "surgical changes only, never delete unrelated code", rule 1
directly contradicts it. Do not silently drop either one — surface the pair and
let the owner decide which wins.
