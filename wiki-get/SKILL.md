---
name: wiki-get
description: Query the LLM wiki — answer a question by navigating index.md and grepping pages, synthesize with citations, optionally save the answer as a new page. Use when user says "wiki-get", "what do I know about", "ask the wiki", "check the wiki", "query wiki", "search the wiki", or in Polish "co wiem o", "zapytaj wiki", "sprawdź w wiki", "poszukaj w wiki", "czy mam coś o". Prefer this over hand-rolled grepping whenever the answer might already be in the vault.
---

# wiki-get — Query the wiki

Answers a question from the wiki. The "Query" operation of the [`llm-wiki`](../llm-wiki/SKILL.md) model.

> Concept: **LLM Wiki** after Andrej Karpathy — https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f

## Step 1 — Locate the vault
Default `<vault-repo>` (or the path from the `NB-WIKI-MEMORY` block). Read `index.md` (the map).

## Step 2 — Find
- Pick candidate pages from `index.md`.
- `grep -ri` across the vault for the question's terms. Open the matched pages and their `[[links]]`.
- This search is **lexical, not semantic**. If the vault mixes languages, grep every language the
  concept could be written in — a page titled "szukanie kontraktów" will never match "job search".
  Try synonyms and the obvious abbreviations before concluding the wiki is silent.

## Step 3 — Synthesize
- Answer concisely, **with citations** to specific pages (`[[Name]]`) and sources.
- If there are contradictions/gaps — say so plainly, do not guess.
- If the wiki has no answer — say so and suggest `wiki-add`.

## Step 4 — (optional) Save the answer
If the answer is valuable and reusable — propose saving it as a new page (via `wiki-add`) and add it to `index.md`.

Do not modify pages on an ordinary query (read only), unless the user asks to save.
