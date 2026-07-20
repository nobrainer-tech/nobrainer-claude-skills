# WIKI — schemat bazy wiedzy (NoBrainer Wiki Memory)

Source-of-truth konwencji dla LLM utrzymującego ten vault jako kompoundującą się bazę wiedzy wg Andreja Karpathy'ego — https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f.
Vault to jednocześnie notatki i wiki. Ten plik mówi każdemu agentowi (Claude Code, Codex, opencode) jak być zdyscyplinowanym kustoszem.

## Model trójwarstwowy
1. **Źródła (raw)** — artykuły, PDF, transkrypty, wklejki. LLM **czyta, nie edytuje**.
2. **Wiki (te .md)** — strony syntetyzujące wiedzę, połączone `[[wikilinkami]]`.
3. **Schemat** — ten plik + `index.md` (mapa) + `log.md` (kronika) + `_inbox/` (poczekalnia).

## Przepływ
```
KLIENT: START → czytaj index.md, grepuj strony · W TRAKCIE → trwały fakt do _inbox/<host>.md
PROMOTER (co godzinę): _inbox/<host>.md → strony wiki → index.md + log.md → git push
```
Fakty lecą do inboxa w trakcie (nie na końcu sesji) — urwana sesja nic nie gubi.

## Operacje
| skill | operacja | co robi |
|-------|----------|---------|
| `nb-add` | Ingest/promocja | źródło/inbox → aktualizuje strony, tworzy brakujące, linkuje, loguje |
| `nb-get` | Query | odpowiada przez index.md + grep, syntetyzuje z cytatami |
| `nb-tidy` | Lint | sieroty, sprzeczności, martwe linki; naprawia + ręczna promocja |

## Konwencje stron
- Jedna strona = jeden byt/koncept. Krótko. H1 = tytuł = nazwa pliku.
- Linkuj hojnie `[[Nazwa]]`. Link do nieistniejącej = TODO, nie błąd.
- Cytuj źródło: `(źródło: [[...]])` lub URL.
- Sprzeczność: `> [!warning] Sprzeczność`. Nieaktualne: `> [!caution] Może nieaktualne (od YYYY-MM-DD)`.
- Daty względne → bezwzględne.

## Inbox (`_inbox/`)
- Jeden plik per maszyna: `_inbox/<hostname>.md` (brak konfliktów git).
- Linia: `- [ ] YYYY-MM-DDTHH:MMZ | <domena/folder> | <fakt> | (źródło)`.
- Promoter oznacza `[x]` i przenosi do stron. Stare `[x]` (>30 dni) czyści `nb-tidy`.

## Mapa folderów (namespacing)
Dziel po **domenie**, nie po projekcie. Granica poufności > granica tematu.
Dostosuj listę do swojego vaultu, np.:
| folder | domena |
|--------|--------|
| `Projects/` | projekty własne |
| `Jobs/` | kontrakty/klienci (POUFNE — nie promować do publicznych miejsc) |
| `Serwery/` | infrastruktura |
| `AI/` | wiedza o AI/agentach |
| `Priv/` | prywatne |

## Sync i wiele maszyn (równorzędne)
Vault to repo git — sync = git (nie iCloud). Każda maszyna równorzędna: czyta, dopisuje do własnego `_inbox/<host>.md`, promuje swój inbox. Promoter: `git pull --rebase` przed, `git push` po.

## Kompatybilność wsteczna
Jeśli istnieje `~/.memsearch/memory/*.md` — potraktuj jak źródło raw i zsyntetyzuj do wiki przez `nb-add`; nie kasuj katalogu.
