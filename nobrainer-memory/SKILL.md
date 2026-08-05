---
name: nobrainer-memory
description: Install NoBrainer Wiki Memory — a persistent, LLM-maintained knowledge wiki (Karpathy "LLM Wiki" pattern) in an Obsidian git vault, wired into every AI client (Claude Code, Codex, opencode) via always-on instructions. Auto-captures durable facts to a per-machine inbox during work; a promoter synthesizes them into interlinked wiki pages. Use when setting up a new machine or when user says "install memory", "nobrainer-memory", "wiki memory", "add memory to claude", "set up wiki memory", "setup wiki".
---

# NoBrainer Wiki Memory — installer

Persistent, cross-client knowledge base built on the **LLM Wiki** pattern by Andrej Karpathy — https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f
Philosophy: **markdown in git is the source of truth.** The LLM maintains coherent pages connected by `[[links]]`; the human steers. Works identically in Claude Code, Codex and opencode, because it relies only on reading a file and appending to a file — not on proprietary hooks.

Replaces the old memsearch-based `nobrainer-memory` (in `archive/nobrainer-memory-memsearch/`). It is backward compatible: detected `~/.memsearch/memory/*.md` files are treated as sources and synthesized into the wiki.

## Architecture

```
EVERY CLIENT  (always-on block in CLAUDE.md / AGENTS.md points at the vault)
  ├─ START:    read index.md (the map) → grep the relevant pages
  └─ DURING:   durable fact → append a line to _inbox/<host>.md   (+ manual "save this")

PROMOTER  (launchd/cron, hourly, each machine promotes ITS OWN inbox)
  _inbox/<host>.md → wiki pages (synthesis, dedup, links) → index.md + log.md → git push
```

Key decisions (baked in, confirmed per machine in Step 0):
- **Read:** `index.md` injected via a static instruction block (not a hook — Codex has them bugged #17532, opencode has no real session-start).
- **Write:** inbox during work + promoter periodically. No dependency on session end.
- **Machines:** peers; a separate inbox file per host = minimum git conflicts.

---

## Step 0 — Ask how it should work (per machine)

Ask and remember in variables:

1. **Vault path?** default `$HOME/wiki-vault` (any existing git repo the user points at). → `VAULT`
2. **Hostname of this machine?** show `hostname -s`, confirm. → `HOST`
3. **Which clients to wire up?** detect the present ones (Step 1) and confirm the list. → `CLIENTS`
4. **Enable the automatic promoter (launchd hourly)?** yes/no. If no — promotion only manually via `wiki-tidy`/`wiki-add`. → `PROMOTER_AUTO`
5. **Promoter interval** (if auto), default 3600 s. → `PROMOTER_INTERVAL`

Do not install anything before the vault path and client list are confirmed.

## Step 1 — Detect environment and clients

```bash
hostname -s; uname -s
echo "claude:   $([ -d "$HOME/.claude" ] && echo yes)"
echo "codex:    $([ -d "$HOME/.codex" ] && echo yes)"
echo "opencode: $([ -d "$HOME/.config/opencode" ] && echo yes)"
echo "memsearch(old): $(ls "$HOME/.memsearch/memory/"*.md 2>/dev/null | wc -l | tr -d ' ') files"
```

Global always-on files per client (research-confirmed 2026-07):
| client | always-on file (global) |
|--------|---------------------------|
| Claude Code | `~/.claude/CLAUDE.md` |
| Codex | `~/.codex/AGENTS.md` (create if missing) |
| opencode | `~/.config/opencode/AGENTS.md` |

## Step 2 — Ensure vault + scaffolding (idempotently)

If `$VAULT` does not exist or is not a git repo — stop and ask (do not create blindly).
Create the missing skeleton files (do NOT overwrite existing ones):

- `WIKI.md` — schema/conventions (see `assets/WIKI.template.md`)
- `index.md` — the map (see `assets/index.template.md`)
- `log.md` — the chronicle (header + init entry)
- `_inbox/<HOST>.md` — this machine's inbox (see `assets/inbox.template.md`, substitute HOST)

```bash
mkdir -p "$VAULT/_inbox"
[ -f "$VAULT/WIKI.md" ]  || cp "$SKILL_DIR/assets/WIKI.template.md"  "$VAULT/WIKI.md"
[ -f "$VAULT/index.md" ] || cp "$SKILL_DIR/assets/index.template.md" "$VAULT/index.md"
[ -f "$VAULT/log.md" ]   || printf '# log — wiki chronicle\n\n' > "$VAULT/log.md"
[ -f "$VAULT/_inbox/$HOST.md" ] || sed "s/{{HOST}}/$HOST/g" "$SKILL_DIR/assets/inbox.template.md" > "$VAULT/_inbox/$HOST.md"
```

## Step 3 — Inject the always-on block into every client (idempotently)

The block is delimited by markers. If the marker is already in the file — replace the content between the markers, do not duplicate.

Marker: `<!-- NB-WIKI-MEMORY:START -->` … `<!-- NB-WIKI-MEMORY:END -->`

Block content (substitute `$VAULT` and `$HOST` with this machine's hard values):

```markdown
<!-- NB-WIKI-MEMORY:START -->
## NoBrainer Wiki Memory
Persistent knowledge base: `$VAULT` (git). Rules: `$VAULT/WIKI.md`.
- **SESSION START:** read `$VAULT/index.md` (the wiki map). Grep specific pages instead of reading the whole vault.
- **DURING:** when you learn a DURABLE fact (decision, configuration, agreement, project state, credentials pointer) append ONE line to `$VAULT/_inbox/$HOST.md`:
  `- [ ] <ISO-UTC> | <folder/domain> | <fact in one sentence> | (source)`
  Only durable facts — not transient session context.
- **"save this to the wiki" / "put this in the wiki":** immediately synthesize into the right page per `WIKI.md` (not just the inbox).
- Append/create pages; do not mass-rewrite others' pages. Keep confidential material (e.g. `private/`) out of public places.
<!-- NB-WIKI-MEMORY:END -->
```

Inject into each of `CLIENTS`:
- Claude Code → append to the end of `~/.claude/CLAUDE.md`
- Codex → append to `~/.codex/AGENTS.md` (create the file if missing)
- opencode → append to `~/.config/opencode/AGENTS.md` (create if missing)

Use `assets/inject-block.sh "$FILE"` (idempotent: replaces between markers or appends).

## Step 4 — Promoter (optional, if PROMOTER_AUTO=yes)

Copy `assets/promote.sh` → `$HOME/.nobrainer-wiki/promote.sh` (chmod +x), configure VAULT/HOST via env in the plist.
Install launchd from `assets/promoter.plist.template` (substitute HOME/VAULT/HOST/INTERVAL) to `~/Library/LaunchAgents/tech.nobrainer.wiki-promoter.plist`.

**Do NOT load launchd without the user's consent** (`launchctl load`). Show the command and let them decide.
The promoter commits and pushes the vault — confirm that is OK (the vault is designed for it, git = undo).

Manual alternative (when PROMOTER_AUTO=no): the user runs `wiki-tidy` / `wiki-add` whenever they want.

## Step 5 — Backward compatibility (old memsearch)

If `~/.memsearch/memory/*.md` is non-empty — treat it as a raw source: read it, synthesize into the wiki via the `wiki-add` logic, log in `log.md`. Do not delete the directory.

## Step 6 — Verification and report

```bash
echo "VAULT: $VAULT ($(git -C "$VAULT" rev-parse --abbrev-ref HEAD))"
ls "$VAULT"/{WIKI.md,index.md,log.md} "$VAULT/_inbox/$HOST.md"
for f in ~/.claude/CLAUDE.md ~/.codex/AGENTS.md ~/.config/opencode/AGENTS.md; do
  [ -f "$f" ] && echo "$f: $(grep -c NB-WIKI-MEMORY "$f") marker(s)"
done
```

Report: which always-on files got the block, whether the promoter is enabled (and the `launchctl load` command), backward-compat state, vault path and branch.

## Operations (separate skills)

- **`wiki-add`** — ingest a source/inbox into the wiki (Ingest/promotion)
- **`wiki-get`** — query the wiki (Query, synthesis with citations)
- **`wiki-tidy`** — housekeeping review (Lint: orphans, contradictions, dead links) + manual inbox promotion

## Error handling

| Problem | Fix |
|---------|-----|
| VAULT is not a git repo | ask the user; do not init on your own |
| missing `~/.codex/AGENTS.md` | create an empty one, then inject the block |
| opencode reads CLAUDE.md (no AGENTS.md) | create `~/.config/opencode/AGENTS.md` anyway — it wins over CLAUDE.md, without duplicating the block |
| launchd does not start | check the paths in the plist (absolute), `launchctl list | grep nobrainer` |
| git conflict on push | the promoter runs `git pull --rebase --autostash` first; on conflict it leaves it and logs |

## Notes

- Public version of the skill: identical, just without hard paths — everything from the Step 0 answers.
- The vault is private; the skill never bakes in its content or folder structure.
- The always-on block is the only integration point — one file per client, idempotent.
