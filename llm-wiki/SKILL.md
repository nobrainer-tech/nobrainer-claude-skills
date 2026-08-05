---
name: llm-wiki
description: >-
  Set up and run a compounding personal knowledge base as an "LLM wiki" in Andrej
  Karpathy's style — a git-versioned vault of curated Markdown pages optimized for
  both humans and LLMs to read and extend. This is the SETUP + METHODOLOGY skill
  and the entry point of the family: it bootstraps the folder layout, the
  index/log/inbox schema, page conventions, and the always-on wiring so every AI
  session reads the index at start and files durable facts back into an inbox.
  Use when the user says "llm wiki", "set up llm wiki", "karpathy wiki",
  "knowledge base setup", "wiki setup", "start a personal wiki", "second brain
  for my agents", "zbuduj wiki", "baza wiedzy", or wants a persistent memory
  their tools compound into over time. For day-to-day operation, hand off to the
  companion skills wiki-get (query), wiki-add (ingest/promote), wiki-tidy (lint).
---

# LLM Wiki — Setup & Methodology

A personal knowledge base you and your LLMs both read from and write to, so
knowledge **compounds** instead of evaporating at the end of each session.
Inspired by Andrej Karpathy's LLM-wiki note
(https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f).

The core idea: stop re-deriving the same facts every conversation. Capture a
durable fact **once**, in a page an LLM can find and cite forever after. The
wiki is plain Markdown in a git repo — no database, no service, no lock-in.

This skill **sets up and explains** the system. It does not do the day-to-day
add/query/lint work — that belongs to three companion skills:

- **`wiki-add`** — ingest a raw source or an inbox line and promote it into a
  curated page (create or extend, add wikilinks, cite the source).
- **`wiki-get`** — answer a question from the wiki: grep the index, follow
  wikilinks, return cited passages, flag when the wiki is silent.
- **`wiki-tidy`** — lint the vault: dead wikilinks, orphan pages, stale dates,
  uncited claims, duplicate concepts, unresolved contradictions.

> `wiki-get` / `wiki-add` / `wiki-tidy` are the canonical names. Install all
> four skills together — this one defines the model the other three assume.

---

## The 3-Layer Model

Keep three layers strictly separate. Mixing them is the #1 way these systems rot.

### Layer 1 — Raw sources (`sources/`)
Unedited captures: article dumps, transcripts, chat exports, PDFs, screenshots,
pasted notes. **Append-only. Never edited, never trusted directly by a query.**
This is the audit trail — every curated claim should trace back here.

### Layer 2 — Curated wiki pages (`pages/`)
The actual knowledge. Human-written or LLM-synthesized Markdown, **one page per
concept**, deduplicated, cross-linked with `[[wikilinks]]`, every non-obvious
claim citing a Layer-1 source. This is what `wiki-get` reads. This is the
product.

### Layer 3 — Schema / control plane
Three special files that make the vault navigable and keep it fed:

- **`index.md`** — the map. A curated table of contents / topic map linking to
  the important pages. **This is the single file every LLM session reads first.**
- **`log.md`** — append-only changelog. One line per meaningful change ("what
  changed, when, why"). Human- and LLM-scannable history.
- **`_inbox/`** — one capture file **per machine**. Where durable facts land
  mid-session before they've been promoted into a real page.

Promotion flows **up**: `sources/` + `_inbox/` → `pages/` → linked from
`index.md`, recorded in `log.md`.

---

## Page Conventions

Every page in `pages/` follows the same shape so both humans and LLMs can parse
it without surprises:

1. **One page per concept.** If a page is trying to explain two things, split it.
   Small, sharply-scoped pages link better and dedupe better.
2. **H1 title equals the filename.** `pages/vector-databases.md` opens with
   `# Vector databases`. Filenames are `kebab-case`; the H1 is the human title.
   This makes `[[wikilinks]]` resolvable by simple filename matching.
3. **`[[wikilinks]]` between concepts.** Link every concept you mention that has
   (or deserves) its own page: `see [[embeddings]] and [[cosine-similarity]]`.
   The link graph is the value — it's how `wiki-get` walks from a question to an
   answer, and how a human browses.
4. **Cite your sources.** Every non-obvious claim ends with a citation to a
   Layer-1 source or an external URL: `RAG recall improved ~12% (source:
   sources/2025-rag-paper.md)` or `(https://example.com/post)`. Uncited claims
   are treated as unverified by `wiki-tidy`.
5. **Mark contradictions explicitly.** When two sources disagree, don't silently
   pick one. Record both and flag it:
   `> ⚠️ CONTRADICTION: [[source-a]] says X, [[source-b]] says Y — unresolved.`
6. **Mark staleness.** Fast-moving facts carry a freshness marker:
   `> ⏳ STALE-RISK: pricing as of 2025-11; re-verify before quoting.`
7. **Absolute dates, never relative.** Write `2025-11-14`, never "yesterday",
   "last week", or "recently". A page is read months later by a model that has
   no idea when it was written. Convert relative → absolute at capture time.
   Prefer ISO-8601 UTC (`2025-11-14T09:30Z`) when the time matters.
8. **Lead with the durable fact.** Put the reusable claim in the first line or
   two; push nuance and history below. LLMs and humans both skim.

### Page template
```markdown
# Concept name

One-line definition a future reader can act on immediately.

## What it is
Body. Cite claims. Link related [[other-concept]] pages.

## Gotchas / contradictions
> ⚠️ CONTRADICTION: ...   (only if any)
> ⏳ STALE-RISK: ...       (only if any)

## Sources
- sources/<file>.md
- https://external-url
```

---

## The Inbox-Per-Machine Flow

Durable facts show up mid-work, on whatever machine you're on. You don't want to
stop and hand-craft a page every time — and you don't want two machines fighting
over the same file in git. So:

- Each machine gets its **own** inbox file: `_inbox/<machine-name>.md`
  (e.g. `_inbox/laptop.md`, `_inbox/desktop.md`, `_inbox/workstation.md`).
- Mid-session, facts are **appended** — never inserted, never reordered — as
  single lines in a fixed format:

  ```
  - [ ] <ISO-UTC> | <topic/area> | <one-sentence durable fact> | (source)
  ```

  Example:
  ```
  - [ ] 2025-11-14T09:30Z | infra | Cloudflare Worker proxy fixes datacenter-IP API bans in ~17 lines | (sources/cf-notes.md)
  ```

- The `- [ ]` checkbox means **unpromoted**. Later, `wiki-add` reads the inbox,
  promotes each line into the right `pages/` page (creating or extending it,
  adding wikilinks and citations), records the change in `log.md`, and checks
  the box `- [x]` (or removes the line).

Because each machine appends to its **own** file, two machines never touch the
same inbox line — so git merges are conflict-free. The per-machine split exists
entirely to make Layer-3 capture safe under multi-machine sync.

Only **durable** facts go in the inbox — decisions, configurations, resolved
findings, stable references. Not transient session chatter.

---

## Git-Based Multi-Machine Sync

The whole vault is one git repo (`<vault-repo>`). That is the entire sync,
history, and backup story — no service required.

- **Start of session:** `git pull` (fast-forward) before reading anything, so
  you're on the latest knowledge.
- **During session:** append to `_inbox/<machine>.md` and, when promoting, edit
  `pages/`, `index.md`, `log.md`.
- **End of session:** commit and push. Commit messages mirror `log.md` intent
  ("add [[worker-proxy]], promote 3 inbox lines").
- **Conflict avoidance:** append-only inbox + per-machine files means the
  high-churn writes never collide. Curated `pages/` edits are low-frequency and
  human-reviewed, so the rare conflict is easy. Keep commits small.
- Optionally protect the promotion step behind a pull-request review if multiple
  people share the vault; solo users can push straight to the main branch.

---

## Bootstrap: Create the Vault

Run this once to lay down the whole structure. Replace `<vault-repo>` with the
target directory and `<machine-name>` with a short id for this machine.

```bash
# 1. Create the repo and layout
mkdir -p <vault-repo>/{pages,sources,_inbox}
cd <vault-repo>
git init

# 2. Seed the schema files (templates below get written into these)
:> index.md
:> WIKI.md
:> log.md
:> "_inbox/<machine-name>.md"

# 3. First commit
git add -A
git commit -m "bootstrap llm wiki: layout + schema"
```

Final layout:
```
<vault-repo>/
├── WIKI.md              # the rules — how to read & write this wiki
├── index.md             # the map — read this FIRST every session
├── log.md               # append-only changelog
├── pages/               # Layer 2: curated concept pages (one per concept)
│   └── <concept>.md
├── sources/             # Layer 1: raw, unedited captures (append-only)
│   └── <capture>.md
└── _inbox/              # Layer 3: unpromoted facts, one file per machine
    └── <machine-name>.md
```

### Starter `index.md`
```markdown
# Wiki Index

The map of this knowledge base. Read this first. Grep for a topic, then open the
linked page. If a topic isn't here, it isn't curated yet — check `_inbox/` and
`sources/`, then promote it with `wiki-add`.

## How to use
- **Query:** use `wiki-get` (grep here → follow [[wikilinks]] → cited answer).
- **Capture:** append durable facts to `_inbox/<this-machine>.md`.
- **Promote:** use `wiki-add` to turn inbox/source material into a page.
- **Lint:** run `wiki-tidy` periodically.

## Topics
<!-- Add links as pages are created, grouped by area -->
- _(empty — add your first [[page]] here)_

## Conventions
See [[WIKI]] for page rules (one concept per page, H1=filename, [[wikilinks]],
cite sources, absolute dates, mark contradictions & staleness).
```

### Starter `WIKI.md`
```markdown
# WIKI — Rules of this knowledge base

This is an LLM-first personal wiki: plain Markdown in git, read and written by
both humans and AI agents. Follow these rules so knowledge compounds instead of
rotting.

## Layers
1. `sources/` — raw captures. Append-only. Never edited. The audit trail.
2. `pages/`   — curated concept pages. Deduped, linked, cited. The product.
3. Schema     — `index.md` (map), `log.md` (changelog), `_inbox/` (capture).

## Page rules
- One concept per page. H1 title == kebab-case filename.
- Link related concepts with [[wikilinks]].
- Cite every non-obvious claim: (source: sources/<file>) or (https://url).
- Absolute dates only (2025-11-14 / ISO-8601 UTC). Never "yesterday".
- Mark contradictions with "⚠️ CONTRADICTION"; staleness with "⏳ STALE-RISK".
- Lead with the durable, reusable fact.

## Capture rules
Append durable facts to `_inbox/<machine>.md`:
`- [ ] <ISO-UTC> | <area> | <fact> | (source)`
Only durable facts. Not session chatter.

## Flow
sources/ + _inbox/  → (wiki-add) → pages/ → link in index.md → note in log.md.
Query with wiki-get. Lint with wiki-tidy. git pull at start, commit+push at end.
```

### Starter `log.md`
```markdown
# Change Log

Append-only. One line per meaningful change: what changed, when (absolute date),
why. Newest at the bottom.

- 2025-11-14 | bootstrap | Created wiki: layout + schema + starter templates.
```

### Starter `_inbox/<machine-name>.md`
```markdown
# Inbox — <machine-name>

Durable facts captured on this machine, awaiting promotion into pages/.
Format: `- [ ] <ISO-UTC> | <area> | <fact> | (source)`
Append only. `wiki-add` promotes these and checks the box.

<!-- facts get appended below -->
```

---

## Wire the Always-On Behavior

The wiki only compounds if **every** session reads the index at start and files
durable facts at capture time — automatically, without being asked. Add this
block to your agent's persistent instruction file (e.g. a global `CLAUDE.md`,
`AGENTS.md`, a system prompt, or a project rules file):

```markdown
## LLM Wiki (persistent knowledge base)

Vault: <vault-repo>  ·  This machine's inbox: <vault-repo>/_inbox/<machine>.md

- START of session: read <vault-repo>/index.md to load the knowledge map.
  Grep specific pages instead of reading the whole vault. `git pull` first.
- DURING session: when you learn a DURABLE fact (a decision, a configuration, a
  resolved finding, a stable reference), append ONE line to this machine's inbox:
  `- [ ] <ISO-UTC> | <area> | <fact in one sentence> | (source)`
  Only durable facts — not transient session context. Do it silently.
- "add this to the wiki" / "promote": invoke `wiki-add` to synthesize the fact
  into the correct page per WIKI.md (create/extend, wikilink, cite, log it).
- To answer from the wiki, invoke `wiki-get`. To lint it, invoke `wiki-tidy`.
- END of session: commit and push.
```

Adjust `<vault-repo>` and `<machine>` to real values. If your harness supports
session-start / session-stop hooks, wire the `git pull` (start) and the inbox
append + commit/push (stop) there so they can't be forgotten.

---

## Operating Loop (day to day)

1. **Session start** — `git pull`; read `index.md`; grep the pages you need.
2. **Work** — as durable facts appear, append them to `_inbox/<machine>.md`.
3. **Query** — need something the wiki might know? `wiki-get`. If it's silent,
   that's a signal to capture it once you learn the answer.
4. **Promote** — `wiki-add` turns inbox lines and raw sources into curated,
   linked, cited pages; updates `index.md` and `log.md`.
5. **Maintain** — run `wiki-tidy` periodically to catch dead links, orphans,
   stale dates, uncited claims, dupes, and unresolved contradictions.
6. **Session end** — commit + push.

---

## Anti-Patterns (why wikis rot)

- **Editing `sources/`.** Breaks the audit trail. Sources are append-only.
- **Dumping raw captures into `pages/`.** Curated ≠ raw. Promote, don't paste.
- **Mega-pages.** "misc-notes.md" with 40 unrelated facts can't be linked or
  deduped. One concept per page.
- **Relative dates.** "recently" is meaningless to a model six months later.
- **Uncited claims.** If it isn't cited, it can't be trusted or re-verified.
- **Silent contradictions.** Two sources disagreeing and you picking one quietly
  destroys trust. Mark it.
- **A stale `index.md`.** If new pages aren't linked from the index, `wiki-get`
  and humans can't find them. Promotion isn't done until the index links it.
- **Shared single inbox across machines.** Guarantees git conflicts. One inbox
  file per machine.

The wiki is worth exactly as much as it is trusted. Cite, date, dedupe, link —
and it compounds.