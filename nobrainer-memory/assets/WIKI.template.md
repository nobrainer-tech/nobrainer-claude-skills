# WIKI — knowledge base schema (NoBrainer Wiki Memory)

Source-of-truth conventions for the LLM maintaining this vault as a compounding knowledge base, after Andrej Karpathy — https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f.
The vault is both notes and a wiki. This file tells every agent (Claude Code, Codex, opencode) how to be a disciplined curator.

## Three-layer model
1. **Sources (raw)** — articles, PDFs, transcripts, pastes. The LLM **reads, does not edit**.
2. **Wiki (these .md)** — pages that synthesize knowledge, connected by `[[wikilinks]]`.
3. **Schema** — this file + `index.md` (the map) + `log.md` (the chronicle) + `_inbox/` (the waiting room).

## Flow
```
CLIENT: START → read index.md, grep pages · DURING → durable fact to _inbox/<host>.md
PROMOTER (hourly): _inbox/<host>.md → wiki pages → index.md + log.md → git push
```
Facts go to the inbox during work (not at session end) — an interrupted session loses nothing.

## Operations
| skill | operation | what it does |
|-------|----------|---------|
| `wiki-add` | Ingest/promotion | source/inbox → updates pages, creates missing ones, links, logs |
| `wiki-get` | Query | answers via index.md + grep, synthesizes with citations |
| `wiki-tidy` | Lint | orphans, contradictions, dead links; fixes + manual promotion |

## Page conventions
- One page = one entity/concept. Keep it short. H1 = title = filename.
- Link generously `[[Name]]`. A link to a non-existent page = TODO, not an error.
- Cite the source: `(source: [[...]])` or a URL.
- Contradiction: `> [!warning] Contradiction`. Stale: `> [!caution] Possibly stale (as of YYYY-MM-DD)`.
- Relative dates → absolute.

## Inbox (`_inbox/`)
- One file per machine: `_inbox/<hostname>.md` (no git conflicts).
- Line: `- [ ] YYYY-MM-DDTHH:MMZ | <domain/folder> | <fact> | (source)`.
- The promoter marks `[x]` and moves it into pages. Old `[x]` (>30 days) is cleaned by `wiki-tidy`.

## Folder map (namespacing)
Split by **domain**, not by project. The confidentiality boundary > the topic boundary.
Adjust the list to your own vault, e.g.:
| folder | domain |
|--------|--------|
| `Projects/` | your own projects |
| `private/` | confidential material (keep out of public places) |
| `Servers/` | infrastructure |
| `AI/` | knowledge about AI/agents |
| `Personal/` | personal |

## Sync and multiple machines (peers)
The vault is a git repo — sync = git (not iCloud). Each machine is a peer: it reads, appends to its own `_inbox/<host>.md`, promotes its own inbox. Promoter: `git pull --rebase` before, `git push` after.

## Backward compatibility
If `~/.memsearch/memory/*.md` exists — treat it as a raw source and synthesize into the wiki via `wiki-add`; do not delete the directory.
