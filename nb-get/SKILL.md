---
name: nb-get
description: Query the NoBrainer Wiki — answer a question by navigating index.md and grepping pages, synthesize with citations, optionally save the answer as a new page. Use when user says "nb-get", "what do I know about", "ask the wiki", "check the wiki", "query wiki".
---

# nb-get — Query the wiki

Answers a question from the NoBrainer Wiki. The "Query" operation from the LLM Wiki model.

> Concept: **LLM Wiki** after Andrej Karpathy — https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f

## Step 1 — Locate the vault
Default `~/GitHub/nobrainer-obsidian` (or the path from the `NB-WIKI-MEMORY` block). Read `index.md` (the map).

## Step 2 — Find
- Pick candidate pages from `index.md`.
- `grep -ri` across the vault for the question's terms. Open the matched pages and their `[[links]]`.

## Step 3 — Synthesize
- Answer concisely, **with citations** to specific pages (`[[Name]]`) and sources.
- If there are contradictions/gaps — say so plainly, do not guess.
- If the wiki has no answer — say so and suggest `nb-add`.

## Step 4 — (optional) Save the answer
If the answer is valuable and reusable — propose saving it as a new page (via `nb-add`) and add it to `index.md`.

Do not modify pages on an ordinary query (read only), unless the user asks to save.
