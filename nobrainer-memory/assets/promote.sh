#!/usr/bin/env bash
# Promoter: _inbox/<host>.md -> wiki pages (synthesis via claude -p) -> git push.
# Run by launchd/cron or manually. Safe: only appends, git = undo.
# Env: VAULT (default ~/GitHub/nobrainer-obsidian), HOST (default hostname -s).
set -uo pipefail

VAULT="${VAULT:-$HOME/GitHub/nobrainer-obsidian}"
HOST="${HOST:-$(hostname -s)}"
INBOX="$VAULT/_inbox/$HOST.md"
LOG="$HOME/.nobrainer-wiki/promote.log"
mkdir -p "$(dirname "$LOG")"
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }

log() { echo "[$(ts)] $*" >> "$LOG"; }

log "promote start host=$HOST vault=$VAULT"

command -v claude >/dev/null 2>&1 || { log "ERROR: 'claude' not in PATH"; exit 1; }
[ -f "$INBOX" ] || { log "no inbox $INBOX"; exit 0; }
grep -q '^- \[ \]' "$INBOX" || { log "inbox empty — nothing to promote"; exit 0; }

cd "$VAULT" || { log "ERROR: cannot enter $VAULT"; exit 1; }
git pull --rebase --autostash >> "$LOG" 2>&1 || log "pull failed, continuing"

PROMPT="You are a wiki curator; read WIKI.md in this directory and follow its conventions.
The file _inbox/$HOST.md contains unchecked '- [ ] ...' lines. For EACH such line:
1. Synthesize the fact into the right wiki page (create the page if missing, or append/update an existing one; link generously [[...]]; cite the source).
2. Add an entry for that page to index.md (if it's missing).
3. Change '- [ ]' to '- [x]' on that inbox line.
At the end, add ONE entry at the TOP of log.md under the header: '## [$(ts)] $HOST promote — <how many items, which pages>'.
Rules: ONLY add/append, do not delete others' content, do not mass-rewrite pages, do not run git. Confidential material stays where it is."

claude -p "$PROMPT" --permission-mode acceptEdits >> "$LOG" 2>&1
log "claude rc=$?"

if ! git diff --quiet || ! git diff --cached --quiet; then
  git add -A
  git commit -m "wiki: promote inbox ($HOST $(ts))" >> "$LOG" 2>&1
  git pull --rebase --autostash >> "$LOG" 2>&1 || log "rebase before push failed"
  if git push >> "$LOG" 2>&1; then log "pushed"; else log "push failed — resolve manually"; fi
else
  log "no changes to commit"
fi
log "promote done"
