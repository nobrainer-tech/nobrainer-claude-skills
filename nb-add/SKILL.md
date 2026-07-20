---
name: nb-add
description: Ingest a source (URL, PDF, pasted text, notes) or promote the inbox into the NoBrainer Wiki — synthesize into interlinked pages, update index.md and log.md. Use when user says "nb-add", "save this to the wiki", "put this in the wiki", "ingest this", "add to knowledge base", "promote inbox".
---

# nb-add — Ingest / promotion into the wiki

Adds knowledge to the NoBrainer Wiki per the conventions in `WIKI.md`. The "Ingest" operation from the LLM Wiki model.

> Concept: **LLM Wiki** after Andrej Karpathy — https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f

## Step 1 — Locate the vault
Default `~/GitHub/nobrainer-obsidian`. If a `NB-WIKI-MEMORY` block is in context, use the path from there. Read `WIKI.md` (rules) and `index.md` (the map).

## Step 2 — Determine the input
- **Source** (URL/PDF/text/file) — read it in full.
- **Inbox promotion** — when the user says "promote inbox": read `_inbox/<host>.md`, take the unchecked `- [ ]` items.

## Step 3 — Synthesize
- `git pull --rebase --autostash` at the start (if a repo).
- For each fact: find the right page via `index.md`/grep. Create it if missing (one page = one concept), or append/update.
- Link generously `[[...]]`. Cite the source `(source: ...)`.
- Contradictions → callout `> [!warning] Contradiction`. Stale → `> [!caution]`.
- Update `index.md` (the page entry). On promotion: change `- [ ]` → `- [x]`.

## Step 4 — Log
Append at the top of `log.md`: `## [<ISO-UTC>] <host> add — <what was added, which pages>`.

## Step 5 — Git
Do not commit without the user's consent. Propose `git add -A && git commit && git push` or leave it to the promoter.

Rules: only add/append, do not delete others' content, do not mass-rewrite pages. Keep confidential material out of public places.
