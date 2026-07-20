---
name: nb-add
description: Ingest a source (URL, PDF, pasted text, notes) or promote the inbox into the NoBrainer Wiki — synthesize into interlinked pages, update index.md and log.md. Use when user says "nb-add", "wrzuć to do wiki", "zapisz do wiki", "zingestuj", "dodaj do bazy wiedzy", "promuj inbox".
---

# nb-add — Ingest / promocja do wiki

Dodaje wiedzę do NoBrainer Wiki wg konwencji z `WIKI.md`. Operacja "Ingest" z modelu LLM Wiki.

> Koncepcja: **LLM Wiki** wg Andreja Karpathy'ego — https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f

## Krok 1 — Zlokalizuj vault
Domyślnie `~/GitHub/nobrainer-obsidian`. Jeśli w kontekście jest blok `NB-WIKI-MEMORY`, użyj ścieżki stamtąd. Przeczytaj `WIKI.md` (zasady) i `index.md` (mapa).

## Krok 2 — Ustal wejście
- **Źródło** (URL/PDF/tekst/plik) — przeczytaj w całości.
- **Promocja inboxa** — gdy user mówi "promuj inbox": przeczytaj `_inbox/<host>.md`, weź niezaznaczone `- [ ]`.

## Krok 3 — Syntetyzuj
- `git pull --rebase --autostash` na starcie (jeśli repo).
- Dla każdego faktu: znajdź właściwą stronę przez `index.md`/grep. Utwórz jeśli brak (jedna strona = jeden koncept), albo dopisz/zaktualizuj.
- Linkuj hojnie `[[...]]`. Cytuj źródło `(źródło: ...)`.
- Sprzeczności → callout `> [!warning] Sprzeczność`. Nieaktualne → `> [!caution]`.
- Aktualizuj `index.md` (wpis strony). Przy promocji: zmień `- [ ]` → `- [x]`.

## Krok 4 — Zaloguj
Dopisz na górze `log.md`: `## [<ISO-UTC>] <host> add — <co doszło, które strony>`.

## Krok 5 — Git
Nie commituj bez zgody usera. Zaproponuj `git add -A && git commit && git push` albo zostaw do promotera.

Zasady: tylko dodawaj/dopisuj, nie kasuj cudzej treści, nie przepisuj stron masowo. Poufne z `Jobs/` zostaje w `Jobs/`.
