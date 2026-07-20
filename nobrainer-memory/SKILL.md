---
name: nobrainer-memory
description: Install NoBrainer Wiki Memory — a persistent, LLM-maintained knowledge wiki (Karpathy "LLM Wiki" pattern) in an Obsidian git vault, wired into every AI client (Claude Code, Codex, opencode) via always-on instructions. Auto-captures durable facts to a per-machine inbox during work; a promoter synthesizes them into interlinked wiki pages. Use when setting up a new machine or when user says "install memory", "nobrainer-memory", "wiki memory", "dodaj pamiec do claude", "zainstaluj memory", "setup wiki".
---

# NoBrainer Wiki Memory — installer

Persistent, cross-client knowledge base built on the **LLM Wiki** pattern by Andrej Karpathy — https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f
Philosophy: **markdown w git jest źródłem prawdy.** LLM utrzymuje spójne, połączone `[[linkami]]` strony; człowiek kieruje. Działa identycznie w Claude Code, Codex i opencode, bo opiera się tylko na czytaniu pliku i dopisaniu pliku — nie na proprietary hookach.

Zastępuje stary memsearch-owy `nobrainer-memory` (w `archive/nobrainer-memory-memsearch/`). Jest wstecznie kompatybilny: wykryte pliki `~/.memsearch/memory/*.md` traktuje jak źródło i syntetyzuje do wiki.

## Architektura

```
KAŻDY KLIENT  (blok always-on w CLAUDE.md / AGENTS.md wskazuje na vault)
  ├─ START:    czytaj index.md (mapa) → grepuj właściwe strony
  └─ W TRAKCIE: trwały fakt → dopisz linię do _inbox/<host>.md   (+ ręczne "wrzuć to")

PROMOTER  (launchd/cron, co godzinę, każda maszyna promuje SWÓJ inbox)
  _inbox/<host>.md → strony wiki (synteza, dedup, linki) → index.md + log.md → git push
```

Kluczowe decyzje (zaszyte, potwierdzane per maszyna w Step 0):
- **Odczyt:** `index.md` wstrzykiwany przez statyczny blok instrukcji (nie hook — Codex ma je zbugowane #17532, opencode nie ma prawdziwego session-start).
- **Zapis:** inbox w trakcie + promoter okresowo. Bez zależności od końca sesji.
- **Maszyny:** równorzędne; osobny plik inbox per host = minimum konfliktów git.

---

## Step 0 — Zapytaj jak ma działać (per maszyna)

Zapytaj i zapamiętaj w zmiennych:

1. **Ścieżka vaultu?** domyślnie `$HOME/GitHub/nobrainer-obsidian`. → `VAULT`
2. **Hostname tej maszyny?** pokaż `hostname -s`, potwierdź. → `HOST`
3. **Których klientów podpiąć?** wykryj obecne (Step 1) i potwierdź listę. → `CLIENTS`
4. **Włączyć automatyczny promoter (launchd co godzinę)?** tak/nie. Jeśli nie — promocja tylko ręcznie przez `nb-tidy`/`nb-add`. → `PROMOTER_AUTO`
5. **Interwał promotera** (jeśli auto), domyślnie 3600 s. → `PROMOTER_INTERVAL`

Nie instaluj nic zanim nie potwierdzi ścieżki vaultu i listy klientów.

## Step 1 — Wykryj środowisko i klientów

```bash
hostname -s; uname -s
echo "claude:   $([ -d "$HOME/.claude" ] && echo yes)"
echo "codex:    $([ -d "$HOME/.codex" ] && echo yes)"
echo "opencode: $([ -d "$HOME/.config/opencode" ] && echo yes)"
echo "memsearch(old): $(ls "$HOME/.memsearch/memory/"*.md 2>/dev/null | wc -l | tr -d ' ') plików"
```

Globalne pliki always-on per klient (potwierdzone research 2026-07):
| klient | plik always-on (globalny) |
|--------|---------------------------|
| Claude Code | `~/.claude/CLAUDE.md` |
| Codex | `~/.codex/AGENTS.md` (utwórz jeśli brak) |
| opencode | `~/.config/opencode/AGENTS.md` |

## Step 2 — Zapewnij vault + scaffolding (idempotentnie)

Jeśli `$VAULT` nie istnieje albo nie jest repo git — zatrzymaj się i zapytaj (nie twórz na ślepo).
Utwórz brakujące pliki szkieletu (NIE nadpisuj istniejących):

- `WIKI.md` — schemat/konwencje (patrz `assets/WIKI.template.md`)
- `index.md` — mapa (patrz `assets/index.template.md`)
- `log.md` — kronika (nagłówek + wpis init)
- `_inbox/<HOST>.md` — inbox tej maszyny (patrz `assets/inbox.template.md`, podstaw HOST)

```bash
mkdir -p "$VAULT/_inbox"
[ -f "$VAULT/WIKI.md" ]  || cp "$SKILL_DIR/assets/WIKI.template.md"  "$VAULT/WIKI.md"
[ -f "$VAULT/index.md" ] || cp "$SKILL_DIR/assets/index.template.md" "$VAULT/index.md"
[ -f "$VAULT/log.md" ]   || printf '# log — kronika wiki\n\n' > "$VAULT/log.md"
[ -f "$VAULT/_inbox/$HOST.md" ] || sed "s/{{HOST}}/$HOST/g" "$SKILL_DIR/assets/inbox.template.md" > "$VAULT/_inbox/$HOST.md"
```

## Step 3 — Wstrzyknij blok always-on do każdego klienta (idempotentnie)

Blok jest ograniczony markerami. Jeśli marker już jest w pliku — podmień zawartość między markerami, nie duplikuj.

Marker: `<!-- NB-WIKI-MEMORY:START -->` … `<!-- NB-WIKI-MEMORY:END -->`

Zawartość bloku (podstaw `$VAULT` i `$HOST` na twarde wartości tej maszyny):

```markdown
<!-- NB-WIKI-MEMORY:START -->
## NoBrainer Wiki Memory
Trwała baza wiedzy: `$VAULT` (git). Zasady: `$VAULT/WIKI.md`.
- **START sesji:** przeczytaj `$VAULT/index.md` (mapa wiki). Grepuj konkretne strony zamiast czytać cały vault.
- **W TRAKCIE:** gdy poznasz TRWAŁY fakt (decyzja, konfiguracja, ustalenie, stan projektu, dane dostępowe-wskaźnik) dopisz JEDNĄ linię do `$VAULT/_inbox/$HOST.md`:
  `- [ ] <ISO-UTC> | <folder/domena> | <fakt w jednym zdaniu> | (źródło)`
  Tylko trwałe fakty — nie chwilowy kontekst sesji.
- **"wrzuć to do wiki" / "zapisz do wiki":** od razu zsyntetyzuj do właściwej strony wg `WIKI.md` (nie tylko inbox).
- Dopisuj/twórz strony; nie przepisuj cudzych masowo. Poufne (`Jobs/`) nie trafia do publicznych miejsc.
<!-- NB-WIKI-MEMORY:END -->
```

Wstrzyknij do każdego z `CLIENTS`:
- Claude Code → dopisz na końcu `~/.claude/CLAUDE.md`
- Codex → dopisz do `~/.codex/AGENTS.md` (utwórz plik jeśli brak)
- opencode → dopisz do `~/.config/opencode/AGENTS.md` (utwórz jeśli brak)

Użyj `assets/inject-block.sh "$FILE"` (idempotentny: podmienia między markerami albo dopisuje).

## Step 4 — Promoter (opcjonalny, jeśli PROMOTER_AUTO=tak)

Skopiuj `assets/promote.sh` → `$HOME/.nobrainer-wiki/promote.sh` (chmod +x), skonfiguruj VAULT/HOST przez env w plist.
Zainstaluj launchd z `assets/promoter.plist.template` (podstaw HOME/VAULT/HOST/INTERVAL) do `~/Library/LaunchAgents/tech.nobrainer.wiki-promoter.plist`.

**NIE ładuj launchd bez zgody użytkownika** (`launchctl load`). Pokaż komendę i pozwól zdecydować.
Promoter commituje i pushuje vault — potwierdź że to OK (vault jest do tego zaprojektowany, git = undo).

Ręczna alternatywa (gdy PROMOTER_AUTO=nie): użytkownik uruchamia `nb-tidy` / `nb-add` gdy chce.

## Step 5 — Kompatybilność wsteczna (stary memsearch)

Jeśli `~/.memsearch/memory/*.md` niepuste — potraktuj jak źródło raw: przeczytaj, zsyntetyzuj do wiki przez logikę `nb-add`, zaloguj w `log.md`. Nie kasuj katalogu.

## Step 6 — Weryfikacja i raport

```bash
echo "VAULT: $VAULT ($(git -C "$VAULT" rev-parse --abbrev-ref HEAD))"
ls "$VAULT"/{WIKI.md,index.md,log.md} "$VAULT/_inbox/$HOST.md"
for f in ~/.claude/CLAUDE.md ~/.codex/AGENTS.md ~/.config/opencode/AGENTS.md; do
  [ -f "$f" ] && echo "$f: $(grep -c NB-WIKI-MEMORY "$f") marker(y)"
done
```

Raport: które pliki always-on dostały blok, czy promoter włączony (i komenda `launchctl load`), stan backward-compat, ścieżka vaultu i branch.

## Operacje (osobne skille)

- **`nb-add`** — wrzuć źródło/inbox do wiki (Ingest/promocja)
- **`nb-get`** — zapytaj wiki (Query, synteza z cytatami)
- **`nb-tidy`** — przegląd porządkowy (Lint: sieroty, sprzeczności, martwe linki) + ręczna promocja inboxa

## Error handling

| Problem | Fix |
|---------|-----|
| VAULT nie jest repo git | zapytaj usera; nie inicjalizuj samowolnie |
| brak `~/.codex/AGENTS.md` | utwórz pusty, potem wstrzyknij blok |
| opencode czyta CLAUDE.md (brak AGENTS.md) | i tak utwórz `~/.config/opencode/AGENTS.md` — wygrywa nad CLAUDE.md, bez dublowania bloku |
| launchd nie startuje | sprawdź ścieżki w plist (bezwzględne), `launchctl list | grep nobrainer` |
| konflikt git przy push | promoter robi `git pull --rebase --autostash` przed; przy konflikcie zostawia i loguje |

## Notes

- Publiczna wersja skilla: identyczna, tylko bez twardych ścieżek — wszystko z odpowiedzi Step 0.
- Vault jest prywatny; skill nigdzie nie zaszywa jego treści ani struktury folderów.
- Blok always-on to jedyny punkt integracji — jeden plik per klient, idempotentny.
