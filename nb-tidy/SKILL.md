---
name: nb-tidy
description: Lint and maintain the NoBrainer Wiki — find orphan pages, contradictions, stale claims, missing links; fix them; also promote pending inbox items. Use when user says "nb-tidy", "tidy the wiki", "review the wiki", "lint wiki", "check wiki consistency".
---

# nb-tidy — Lint / housekeeping review

Keeps the NoBrainer Wiki consistent. The "Lint" operation from the LLM Wiki model. This is the bookkeeping a human does not do — the LLM does.

> Concept: **LLM Wiki** after Andrej Karpathy — https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f

## Step 1 — Locate the vault
Default `~/GitHub/nobrainer-obsidian` (or the path from the `NB-WIKI-MEMORY` block). `git pull --rebase --autostash`. Read `WIKI.md`, `index.md`.

## Step 2 — Scan (report before fixing)
- **Orphans:** pages nobody links to (grep `[[Name]]`).
- **Contradictions:** pages saying different things about the same subject.
- **Dead claims:** marked `> [!caution]` or obviously stale.
- **Missing links:** mentions of an entity without a `[[link]]`.
- **Dangling links:** `[[X]]` to non-existent pages (candidates to create).
- **index.md vs reality:** pages missing from the index / entries without files.
- **Inbox:** unchecked `- [ ]` in `_inbox/*.md` (to promote) and processed `[x]` >30 days old (to remove).

## Step 3 — Fix
- Add missing links, create valuable dangling pages, add orphans to `index.md` or merge them.
- Resolve contradictions (or leave a callout if it needs the user's decision — ask).
- Promote unchecked inbox items (like `nb-add` promotion), mark `[x]`.
- Remove old `[x]` from the inbox.
- Sync `index.md`.

## Step 4 — Log
Append at the top of `log.md`: `## [<ISO-UTC>] <host> tidy — <what was fixed, how many promotions>`.

## Step 5 — Git
Propose commit+push (do not do it without the user's consent, unless running as the promoter).
