#!/usr/bin/env bash
# Promoter: _inbox/<host>.md -> strony wiki (synteza przez claude -p) -> git push.
# Uruchamiany przez launchd/cron albo ręcznie. Bezpieczny: tylko dopisuje, git = undo.
# Env: VAULT (domyślnie ~/GitHub/nobrainer-obsidian), HOST (domyślnie hostname -s).
set -uo pipefail

VAULT="${VAULT:-$HOME/GitHub/nobrainer-obsidian}"
HOST="${HOST:-$(hostname -s)}"
INBOX="$VAULT/_inbox/$HOST.md"
LOG="$HOME/.nobrainer-wiki/promote.log"
mkdir -p "$(dirname "$LOG")"
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }

log() { echo "[$(ts)] $*" >> "$LOG"; }

log "promote start host=$HOST vault=$VAULT"

command -v claude >/dev/null 2>&1 || { log "ERROR: brak 'claude' w PATH"; exit 1; }
[ -f "$INBOX" ] || { log "brak inboxa $INBOX"; exit 0; }
grep -q '^- \[ \]' "$INBOX" || { log "inbox pusty — nic do promocji"; exit 0; }

cd "$VAULT" || { log "ERROR: nie mogę wejść do $VAULT"; exit 1; }
git pull --rebase --autostash >> "$LOG" 2>&1 || log "pull nieudany, kontynuuję"

PROMPT="Jesteś kustoszem wiki; przeczytaj WIKI.md w tym katalogu i stosuj jego konwencje.
W pliku _inbox/$HOST.md są niezaznaczone linie '- [ ] ...'. Dla KAŻDEJ takiej linii:
1. Zsyntetyzuj fakt do właściwej strony wiki (utwórz stronę jeśli brak, albo dopisz/zaktualizuj istniejącą; hojnie linkuj [[...]]; cytuj źródło).
2. Uzupełnij index.md o wpis tej strony (jeśli go brak).
3. Zmień '- [ ]' na '- [x]' w tej linii inboxa.
Na końcu dopisz JEDEN wpis na GÓRZE log.md pod nagłówkiem: '## [$(ts)] $HOST promote — <ile pozycji, które strony>'.
Zasady: TYLKO dodawaj/dopisuj, nie kasuj cudzej treści, nie przepisuj stron masowo, nie wykonuj git. Poufne z Jobs/ zostaje w Jobs/."

claude -p "$PROMPT" --permission-mode acceptEdits >> "$LOG" 2>&1
log "claude rc=$?"

if ! git diff --quiet || ! git diff --cached --quiet; then
  git add -A
  git commit -m "wiki: promote inbox ($HOST $(ts))" >> "$LOG" 2>&1
  git pull --rebase --autostash >> "$LOG" 2>&1 || log "rebase przed push nieudany"
  if git push >> "$LOG" 2>&1; then log "pushed"; else log "push nieudany — rozwiąż ręcznie"; fi
else
  log "brak zmian do commita"
fi
log "promote done"
