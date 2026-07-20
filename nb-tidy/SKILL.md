---
name: nb-tidy
description: Lint and maintain the NoBrainer Wiki — find orphan pages, contradictions, stale claims, missing links; fix them; also promote pending inbox items. Use when user says "nb-tidy", "posprzątaj wiki", "przejrzyj wiki", "lint wiki", "sprawdź spójność wiki".
---

# nb-tidy — Lint / przegląd porządkowy

Utrzymuje spójność NoBrainer Wiki. Operacja "Lint" z modelu LLM Wiki. To jest bookkeeping którego człowiek nie robi — LLM tak.

> Koncepcja: **LLM Wiki** wg Andreja Karpathy'ego — https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f

## Krok 1 — Zlokalizuj vault
Domyślnie `~/GitHub/nobrainer-obsidian` (albo ścieżka z bloku `NB-WIKI-MEMORY`). `git pull --rebase --autostash`. Przeczytaj `WIKI.md`, `index.md`.

## Krok 2 — Skanuj (raport przed naprawą)
- **Sieroty:** strony do których nikt nie linkuje (grep `[[Nazwa]]`).
- **Sprzeczności:** strony mówiące co innego o tym samym.
- **Martwe twierdzenia:** oznaczone `> [!caution]` lub oczywiście nieaktualne.
- **Brakujące linki:** wzmianki bytu bez `[[linku]]`.
- **Wiszące linki:** `[[X]]` do nieistniejących stron (kandydaci do utworzenia).
- **index.md vs rzeczywistość:** strony spoza indeksu / wpisy bez plików.
- **Inbox:** niezaznaczone `- [ ]` w `_inbox/*.md` (do promocji) i przetworzone `[x]` >30 dni (do usunięcia).

## Krok 3 — Napraw
- Dodaj brakujące linki, utwórz wartościowe wiszące strony, dopisz sieroty do `index.md` lub połącz.
- Rozstrzygnij sprzeczności (lub zostaw callout jeśli wymaga decyzji usera — zapytaj).
- Wypromuj niezaznaczone pozycje inboxa (jak `nb-add` promocja), oznacz `[x]`.
- Usuń stare `[x]` z inboxa.
- Zsynchronizuj `index.md`.

## Krok 4 — Zaloguj
Dopisz na górze `log.md`: `## [<ISO-UTC>] <host> tidy — <co naprawiono, ile promocji>`.

## Krok 5 — Git
Zaproponuj commit+push (nie rób bez zgody usera, chyba że działa jako promoter).
