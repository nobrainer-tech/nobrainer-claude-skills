---
name: nb-get
description: Query the NoBrainer Wiki — answer a question by navigating index.md and grepping pages, synthesize with citations, optionally save the answer as a new page. Use when user says "nb-get", "co wiem o", "zapytaj wiki", "sprawdź w wiki", "query wiki".
---

# nb-get — Query wiki

Odpowiada na pytanie z NoBrainer Wiki. Operacja "Query" z modelu LLM Wiki.

> Koncepcja: **LLM Wiki** wg Andreja Karpathy'ego — https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f

## Krok 1 — Zlokalizuj vault
Domyślnie `~/GitHub/nobrainer-obsidian` (albo ścieżka z bloku `NB-WIKI-MEMORY`). Przeczytaj `index.md` (mapa).

## Krok 2 — Znajdź
- Wybierz kandydujące strony z `index.md`.
- `grep -ri` po vaultcie dla terminów pytania. Otwórz trafione strony i ich `[[linki]]`.

## Krok 3 — Syntetyzuj
- Odpowiedz zwięźle, **z cytatami** do konkretnych stron (`[[Nazwa]]`) i źródeł.
- Jeśli są sprzeczności/luki — powiedz to wprost, nie zgaduj.
- Jeśli wiki nie ma odpowiedzi — powiedz i zaproponuj `nb-add`.

## Krok 4 — (opcjonalnie) Zapisz odpowiedź
Jeśli odpowiedź jest wartościowa i wielokrotnego użytku — zaproponuj zapis jako nowa strona (przez `nb-add`) i dopisz do `index.md`.

Nie modyfikuj stron przy zwykłym query (tylko czytasz), chyba że user poprosi o zapis.
