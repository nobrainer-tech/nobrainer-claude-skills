---
name: deep-audit
description: Universal evidence-based post-implementation verification. Backward line-by-line review, concrete value traces, caller audits with shown grep output. Works with any language/framework. Use after completing a feature/refactor/fix, BEFORE committing.
effort: max
argument-hint: "[quick | standard | deep]"
---

Dokladna weryfikacja wsteczna wykonanej pracy. Wymusza line-by-line review, kreatywne metody sprawdzania i aktywne szukanie bledow. Uniwersalna - dziala z kazdym jezykiem i frameworkiem.

Triggery: "audit", "analiza", "sprawdz dokladnie", "wsteczne testy", "szukaj bledow", "zweryfikuj", "line by line", "linijka po linijce", "review changes"

## Kiedy uzywac

Po zakonczeniu implementacji (feature, refactor, fix, split) - PRZED commitem. Skill wymusza weryfikacje, ktorej nie zastapi kompilator/linter.

## Krok 0 - Detect & Triage

### Auto-detect projektu

Wykryj srodowisko automatycznie:

```bash
PROJECT_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$PROJECT_ROOT"

# Detect language/framework
[ -f "tsconfig.json" ] && LANG="typescript"
[ -f "package.json" ] && FRAMEWORK="node"
[ -f "pom.xml" ] && LANG="java" && FRAMEWORK="maven"
[ -f "build.gradle" ] && LANG="java" && FRAMEWORK="gradle"
[ -f "requirements.txt" -o -f "pyproject.toml" -o -f "setup.py" ] && LANG="python"
[ -f "go.mod" ] && LANG="go"
[ -f "Cargo.toml" ] && LANG="rust"
[ -f "Gemfile" ] && LANG="ruby"
[ -f "composer.json" ] && LANG="php"
[ -f "*.sln" -o -f "*.csproj" ] && LANG="csharp"
```

Zanotuj: PROJECT_ROOT, LANG, FRAMEWORK - uzywaj ich w kolejnych krokach.

### Wybierz tryb

Ocen ryzyko zmian:

| Sygnal | Tryb |
|---|---|
| Tylko CSS/style, docs, config, dotfiles | QUICK - kroki 1, 5, 6 |
| UI components, helpers, utilities (bez core logic) | STANDARD - kroki 1-6 |
| Core business logic, API contracts, auth, payment, database migrations, security, split 1->N | DEEP - kroki 1-6 + krok 3b |

Jesli $ARGUMENTS = "quick" lub "deep" -> wymusz ten tryb.

### Cross-reference z planem

Sprawdz czy istnieje plan file:

```bash
PLAN=$(find . .claude ~/.claude -maxdepth 3 -name "*plan*" -newer "$(git log -1 --format=%aI)" 2>/dev/null | head -1)
[ -n "$PLAN" ] && echo "PLAN: $PLAN" || echo "NO PLAN"
```

Jesli plan istnieje - przeczytaj go i wyciagnij:
- Liste "Done when" criteria per krok - bedziesz je weryfikowac w Kroku 2
- Liste "Krytyczne pulapki" - bedziesz je sprawdzac w Kroku 4
- Integration test matrix - uruchomisz go w Kroku 5
- Evidence log - porownaj z aktualnym stanem kodu

Plan jest checklista. Analiza jest audytem tej checklisty.

## Krok 1 - Zbierz scope

Zidentyfikuj WSZYSTKIE pliki zmienione/stworzone w tej sesji:

```bash
cd "$PROJECT_ROOT" && { git diff --name-only; git diff --cached --name-only; git ls-files --others --exclude-standard; } | sort -u
```

Jesli brak zmian -> "Brak zmian do analizy." i zakoncz.

Dla kazdego pliku zanotuj:
- Sciezka i domena (ui / api / core / db / config / test / infra)
- Czy to NOWY plik czy MODYFIKACJA istniejacego
- Ile linii zmienionych (`git diff --stat`)

## Krok 1b - Predict the bug (STANDARD + DEEP)

ZANIM przeczytasz kod - na podstawie samego scope'u i typu zmian, napisz 2-3 przewidywania gdzie spodziewasz sie buga. Przyklady:

- "Zmiana w hook + nowy komponent -> prawdopodobnie nowa sygnatura nie pasuje do jakiegos consumera"
- "Split pliku -> prawdopodobnie zgubiony eksport lub zmieniony return type"
- "Zmiana warunku guard -> prawdopodobnie odwrocona logika lub brakujacy edge case"
- "Math/obliczenia -> prawdopodobnie division by zero lub Infinity"
- "SQL migration -> prawdopodobnie brak rollback lub niespojne z ORM models"
- "API endpoint change -> prawdopodobnie frontend nie zaktualizowany"

Zapisz przewidywania. Po review - sprawdz czy trafiles. Jesli NIE trafiles w zadne - szukaj dalej, bo bug jest gdzie indziej niz myslales.

## Krok 1c - Name & Path Verification (STANDARD + DEEP)

ZANIM zaczniesz review kodu - zweryfikuj ze kazdy nowy symbol w zmienionych plikach faktycznie istnieje pod ta nazwa.

Dla kazdego zmienionego pliku:
1. Wylistuj NOWE importy, wywolania funkcji, referencje do zewnetrznych symboli
2. Dla KAZDEGO - grep potwierdza ze symbol istnieje pod ta dokladna nazwa w target file

Pokaz literal output:

```
- import { handleSeasonEnd } from './GameScene':
  $ grep -n "handleSeasonEnd" GameScene.ts
  (no results)
  $ grep -n "handleSeason" GameScene.ts
  1823:  handleSeasonEnded() {
  -> BUG: literowka w imporcie. Poprawna nazwa: handleSeasonEnded

- seasonStore.setSeasonEndReached(true):
  $ grep -n "setSeasonEndReached" seasonStore.ts
  52:  setSeasonEndReached: (flag: boolean) => set({ seasonEndReached: flag }),
  -> OK
```

To lapie: literowki, "podobne ale bledne" nazwy, stale paths po refactorze, nieistniejace eksporty.

## Krok 2 - Backward line-by-line review (STANDARD + DEEP)

ZASADA FRESHNESS: Czytaj pliki z dysku (Read tool), NIGDY z pamieci kontekstu. Twoja pamiec tego co napisales jest obarczona tym samym biasem ktory mogl spowodowac buga. Plik na dysku jest prawda - twoja pamiec nie.

Dla KAZDEGO zmienionego pliku (od ostatniego do pierwszego - kolejnosc wsteczna):

1. Przeczytaj CALY plik z dysku (Read tool - nie fragment, nie z pamieci)
2. Przeczytaj diff tego pliku: `git diff [plik]` (dla NOWYCH plikow: diff nie istnieje - czytaj caly plik jako "zmieniony", ze szczegolna uwaga na importy, eksporty i typy)
3. Dla KAZDEJ zmienionej linii zadaj sobie pytania:
   - Czy ta linia robi dokladnie to, co powinna?
   - Czy nie ma literowki w nazwie zmiennej/funkcji/property?
   - Czy typy sa poprawne (nie any, nie brakuje await, nie jest string zamiast number)?
   - Czy warunek logiczny jest odwrotny (np. ! za duzo/za malo, && vs ||)?
   - Czy import/require path jest poprawny i plik docelowy istnieje?
   - Czy to nie jest dead code (nieosiagalny, nieuzywany)?
4. Jesli byl plan z "Done when" criteria - zweryfikuj kazde kryterium dla tego kroku. Nie "czy sie kompiluje" ale "czy zrobiono to co plan mowil".

WAZNE: Nie skanuj - CZYTAJ. Kazda linia. Zapisuj znalezione problemy na biezaco.

## Krok 3 - Kreatywna weryfikacja krzyzowa (STANDARD + DEEP)

### 3a - Obowiazkowy caller audit

Dla KAZDEJ zmienionej sygnatury funkcji lub eksportu:

```bash
grep -rn "functionName" "$PROJECT_ROOT/src/" "$PROJECT_ROOT/lib/" "$PROJECT_ROOT/app/" 2>/dev/null
```

Pokaz literal output grepa w raporcie. Dla kazdego callera - potwierdz ze sygnatura pasuje. Nie "5 callerow, OK" ale:

```
Caller audit: setCurrentSeason()
$ grep -rn "setCurrentSeason" src/
chainDataService.ts:234: setCurrentSeason(season)
seasonPoller.ts:67: setCurrentSeason(data)
handleSeasonStarted.ts:12: setCurrentSeason(newSeason)
[...]
-> 9 callerow, sygnatury zgodne (Season type)
```

Jesli callerow jest >15 - pokaz pierwsze 5 + "i [N] wiecej, spot-check 3 losowych: [wyniki]".

### 3b - Metody weryfikacji per typ zmiany (DEEP)

Dla kazdego pliku dobierz DODATKOWA metode sprawdzenia:

| Typ zmiany | Metoda weryfikacji |
|---|---|
| Nowy plik wyekstrahowany z istniejacego | Porownaj z oryginalem: `git show HEAD:[oryginal]` -> diff funkcja po funkcji. Czy cos zgubione? Czy return types identyczne? |
| Zmiana w hook/store/state | Grep wszystkich konsumentow + pokaz output |
| Nowa funkcja | Concrete value trace (patrz nizej) |
| Zmiana warunku/guard | Truth table: wypisz kombinacje inputow i sciezki |
| Zmiana w SQL/migration | Sprawdz rollback, indeksy, foreign keys, NULL handling |
| Zmiana API endpoint | Sprawdz czy klient/frontend uzywa nowej sygnatury |
| Zmiana CSS/style | Sprawdz czy klasy istnieja, czy nie ma konfliktu, czy responsive dziala |
| Zmiana importow | `grep -rn "from.*[nazwa_pliku]"` - czy ktos importuje stary path? |
| Split pliku 1->N | Wylistuj WSZYSTKIE eksporty oryginalu -> potwierdz ze kazdy eksport ma nowe miejsce |
| Zmiana w security/auth | Sprawdz access control, token validation, input sanitization |
| Zmiana config/env | Sprawdz czy nowe zmienne sa w .env.example, CI/CD, docs |

### 3c - Concrete value trace

Wybierz funkcje i przepusc przez nie KONKRETNE wartosci:
- DEEP: kazda nietrywialna funkcja w scope
- STANDARD: minimum 2 (najryzykowniejsza + 1 losowa)

```
Trace: formatMarketCap(0.00000001)
-> value = 0.00000001, threshold check: < 0.01 -> true
-> return "< 0.01" OK

Trace: formatMarketCap(Infinity)
-> value = Infinity, threshold check: Infinity < 0.01 -> false
-> toFixed(2) -> "Infinity" - BUG: brak guard na !isFinite()
```

W raporcie pokaz trace - nie pomin go nawet jesli nie znalazl buga.

### 3d - "Explain to a junior" (STANDARD + DEEP)

Dla kazdej nietrywialnej funkcji w zmienionych plikach:

1. Przeczytaj TYLKO sygnature (nazwa + params + return type) - napisz jednym zdaniem co ta funkcja POWINNA robic
2. Przeczytaj body - napisz jednym zdaniem co ta funkcja FAKTYCZNIE robi
3. Porownaj oba zdania - rozbieznosc = bug lub niejasna intencja

To lapie bugi gdzie kod "wyglada dobrze" ale robi cos innego niz zamierzono.

## Krok 4 - Szukanie ukrytych bledow (STANDARD + DEEP)

Aktywnie szukaj tych kategorii problemow (check kazda):

### A. Consistency errors

- Nazwy zmiennych/funkcji - czy konsystentne w calym scope? (np. isActive vs active vs isEnabled)
- Formatowanie - czy nowy kod uzywa tych samych wzorcow co reszta pliku?

### B. Edge cases

- Co sie stanie z null/undefined/0/''/[] jako input?
- Co sie stanie z Infinity/NaN (JS/TS) lub None/float('inf') (Python)?
- Co sie stanie gdy tablica/lista jest pusta?
- Co sie stanie przy concurrent calls (race condition)?
- Co sie stanie z very large input (memory, timeout)?

### C. Integration errors

- Czy zmieniony interface/type jest uzywany gdzie indziej? (Grep na nazwe typu - pokaz output)
- Czy usuniety eksport nie jest importowany w innym pliku? (grep - pokaz output)
- Czy zmieniona sygnatura funkcji pasuje do wszystkich call sites? (z Kroku 3a - potwierdz)

### D. Copy-paste errors

- Czy nie skopiowalem zmiennej z innego bloku i nie zapomnialem zmienic nazwy?
- Czy warunki w if/else if/else nie sprawdzaja tego samego?

### E. Znane pulapki z regul projektu

Sprawdz czy istnieja rules/CLAUDE.md w projekcie:

```bash
find "$PROJECT_ROOT" -maxdepth 2 -name "CLAUDE.md" -o -name "*.md" -path "*/.claude/rules/*" 2>/dev/null
```

Przeczytaj odpowiedni plik regul dla domeny zmienianych plikow. Dla KAZDEJ reguly ktora ma zastosowanie - CYTUJ w raporcie z literal grep output:

```
CLAUDE.md: "Never use any type"
  $ grep -n ": any" [zmienione-pliki]
  (no results)
  -> OK

CLAUDE.md: "Always validate input at API boundary"
  $ grep -n "req.body\|req.params\|req.query" [zmienione-pliki]
  handler.ts:42: const id = req.params.id
  -> NARUSZENIE: brak walidacji
```

### F. Plan traps verification (jesli byl /plan)

Jesli plan mial sekcje "Krytyczne pulapki" - zweryfikuj KAZDA z literal grep output.

## Krok 5 - Weryfikacja maszynowa

Uruchom odpowiednie narzedzia na podstawie wykrytego LANG:

```bash
cd "$PROJECT_ROOT"

# TypeScript/JavaScript
if [ -f "tsconfig.json" ]; then
  npx tsc --noEmit 2>&1 | tail -20
fi
if [ -f "package.json" ]; then
  CHANGED=$({ git diff --name-only; git diff --cached --name-only; } | sort -u | grep -E '\.(ts|tsx|js|jsx)$' | tr '\n' ' ')
  [ -n "$CHANGED" ] && npx eslint $CHANGED 2>&1 | tail -20
fi

# Python
if [ -n "$(find . -name '*.py' -newer .git/HEAD 2>/dev/null | head -1)" ]; then
  CHANGED_PY=$({ git diff --name-only; git diff --cached --name-only; } | sort -u | grep '\.py$' | tr '\n' ' ')
  [ -n "$CHANGED_PY" ] && python3 -m py_compile $CHANGED_PY 2>&1
  command -v ruff >/dev/null && [ -n "$CHANGED_PY" ] && ruff check $CHANGED_PY 2>&1 | tail -20
  command -v mypy >/dev/null && [ -n "$CHANGED_PY" ] && mypy $CHANGED_PY 2>&1 | tail -20
fi

# Java
if [ -f "pom.xml" ]; then
  mvn compile -q 2>&1 | tail -20
elif [ -f "build.gradle" ]; then
  ./gradlew compileJava -q 2>&1 | tail -20
fi

# Go
if [ -f "go.mod" ]; then
  go vet ./... 2>&1 | tail -20
fi

# Rust
if [ -f "Cargo.toml" ]; then
  cargo check 2>&1 | tail -20
fi

# Universal checks na nowych plikach
NEW_FILES=$(git ls-files --others --exclude-standard | grep -vE '\.(png|jpg|gif|svg|ico|woff|ttf|eot)$')
[ -n "$NEW_FILES" ] && file $NEW_FILES | grep -i crlf || echo "OK: no CRLF"
```

Jesli jakies narzedzie nie jest zainstalowane - pomin i zanotuj w raporcie.

## Krok 6 - Raport

META-CHECK przed pisaniem raportu: Przejrzyj kazdy claim ktory zamierzasz napisac. Czy masz na niego dowod z narzedzia (grep output, Read output, compiler output)? Jesli nie - nie pisz "OK", wroc i sprawdz, albo napisz "NIE ZWERYFIKOWANO".

Przedstaw wyniki w formacie:

```
## Analiza wsteczna - [data]

### Tryb: QUICK / STANDARD / DEEP
### Srodowisko: [LANG] / [FRAMEWORK] / [PROJECT_ROOT]

### Scope
- [N] plikow zmienionych, [M] nowych
- Domeny: [lista]

### Przewidywania vs rzeczywistosc (STANDARD/DEEP)
- Przewidywanie 1: [opis] -> TRAFIONE / PUDLO
- Przewidywanie 2: [opis] -> TRAFIONE / PUDLO

### Name & Path Verification (STANDARD/DEEP)
- [symbol]: $ grep ... -> [output] -> OK / BUG

### Caller audit (STANDARD/DEEP)
- [funkcja/eksport]: $ grep ... -> [N] callerow, [podsumowanie]

### Concrete value traces (STANDARD/DEEP)
- [funkcja]([wartosci]) -> [wynik trace] -> OK / BUG

### Znalezione problemy

| # | Plik | Linia | Problem | Severity | Dowod |
|---|------|-------|---------|----------|-------|
| 1 | ... | ... | ... | CRITICAL / WARNING / INFO | [$ komenda + output] |

### Weryfikacja maszynowa
- compiler: PASS / FAIL (N errors)
- linter: PASS / FAIL (N warnings)
- type checker: PASS / FAIL / SKIPPED
- line endings: PASS / FAIL

### Reguly projektu (STANDARD/DEEP)
- [plik] [sekcja]: "[regula]" -> [$ komenda + output] -> OK / NARUSZENIE

### Plan verification (jesli byl /plan)
- Done when criteria: [N]/[M] spelnione
- Krytyczne pulapki: [N]/[M] zweryfikowane

### Blind spots - czego NIE zweryfikowalem
- [jawna lista]

### Podsumowanie
[1-2 zdania: ogolna ocena jakosci + czy jest gotowe do commita]
```

Jesli 0 problemow -> "Analiza czysta. Gotowe do commita."
Jesli CRITICAL -> napraw PRZED commitem.
Jesli WARNING -> zaproponuj fix, czekaj na decyzje.

## Krok 1.5 — Orchestrator pre-processing (STANDARD + DEEP)

Before spawning subagents, the orchestrator extracts structured inputs:

### 1.5a — Extract S1 (structural) and S2 (semantic) inputs from diffs

```bash
cd "$PROJECT_ROOT"

# S1 — Structural: what changed physically
CHANGED_FILES=$({ git diff --name-only; git diff --cached --name-only; } | sort -u)
CHANGED_SIGNATURES=$(git diff -U0 | grep -E '^\+.*(function |def |func |fn |class |interface |type |export )' | head -30)
CHANGED_IMPORTS=$(git diff -U0 | grep -E '^\+.*(import |require\(|from )' | head -20)

# S2 — Semantic: what the changes mean
CHANGE_TYPE="unknown"
echo "$CHANGED_FILES" | grep -q "migration\|schema\|\.sql" && CHANGE_TYPE="database"
echo "$CHANGED_FILES" | grep -q "auth\|session\|token\|jwt" && CHANGE_TYPE="security"
echo "$CHANGED_FILES" | grep -q "config\|\.env\|settings" && CHANGE_TYPE="configuration"
echo "$CHANGED_FILES" | grep -q "api/\|route\|endpoint\|handler" && CHANGE_TYPE="api"
```

### 1.5b — Load context files

```bash
PLAN=$(find "$PROJECT_ROOT" -maxdepth 3 -name "*plan*" -o -name "*todo*" 2>/dev/null | head -3)
RULES=$(find "$PROJECT_ROOT" -maxdepth 2 -name "CLAUDE.md" -o -name "AGENTS.md" -o -name "*.md" -path "*/.claude/rules/*" 2>/dev/null)
```

Pass S1, S2, CHANGE_TYPE, PLAN, and RULES to every subagent.

## Strategia paralelizacji (STANDARD + DEEP)

Gdy scope > 5 plikow, rozdziel prace na subagentow (Agent tool). Orchestrator laczy wyniki w jeden raport.

### Grouping heuristic (4 steps)

Before spawning, group files into subagent clusters:

1. **Split detection**: If a file was split (1->N), ALL resulting files go to ONE subagent — caller audit needs full context of both sides.
2. **Producer-consumer**: If changes touch both a data producer (API route, DB query, service) and its consumer (component, handler, page), pair them in one subagent.
3. **Cross-import**: If file A imports from changed file B, they go together. Check: `grep -l "from.*[changed-file]" $CHANGED_FILES`.
4. **Directory grouping**: Remaining files grouped by directory/domain (max 4 files per subagent).

### Podział pracy

1. Po Kroku 1 + 1.5 — podziel pliki wg heurystyki powyzej
2. Spawn subagentow rownolegle (max 10):
   - Kazdy subagent dostaje structured prompt (szablon ponizej)
   - Kazdy wykonuje: Name & Path Verification, Backward review, Caller audit, Value trace, Hidden bugs
   - Kazdy zwraca structured output (format ponizej)
3. Orchestrator:
   - Zbiera wyniki od wszystkich subagentow
   - Runs 5-step merge (ponizej)
   - Uruchamia Krok 5 (weryfikacja maszynowa) — centralne
   - Laczy w jeden raport (Krok 6)

### Prompt template for subagents

```
<context>
PROJECT_ROOT: [path]
LANG: [detected language]
MODE: [STANDARD or DEEP]
CHANGE_TYPE: [from Step 1.5a]
S1_CHANGED_FILES: [file list from this subagent's cluster]
S1_CHANGED_SIGNATURES: [relevant signatures]
S1_CHANGED_IMPORTS: [relevant imports]
PLAN: [plan file content or "NONE"]
DOMAIN_RULES: [relevant CLAUDE.md rules or "NONE"]
</context>

<task>
Execute Steps 1c through 4 of the deep-audit skill on your assigned files:
1. Name & Path Verification — verify every new symbol exists under that exact name
2. Backward line-by-line review — read EVERY changed line from disk, reverse order
3. Caller audit — grep all callers for changed signatures, show literal output
4. Value trace — run concrete values through non-trivial functions
5. Hidden bug hunt — consistency, edge cases, integration, copy-paste, project rules
</task>

<rules>
1. Read files from DISK (Read tool), NEVER from memory.
2. Every claim needs evidence: $ command + literal output.
3. "Checked, OK" without grep output = NOT checked.
4. Pick verification methods appropriate for file types (caller audit for signatures, truth table for conditions, value trace for functions).
</rules>

<output_format>
Return a structured list of findings:

FINDING: [one-line description]
FILE: [path]
LINE: [number]
SEVERITY: CRITICAL / WARNING / INFO
EVIDENCE: [$ command + literal output]
CONFLICTS_WITH: [subagent number, or NONE]

If no issues found:
CLEAN: [list of files reviewed]
METHODS_USED: [which verification methods applied]
EVIDENCE: [$ commands run to confirm clean]
</output_format>
```

### 5-step merge algorithm

After all subagents complete:

#### 3.1 — Deduplicate
Group findings pointing to the same file:line. Keep the finding with highest severity and most evidence.

#### 3.2 — Detect conflicts
Scan all `CONFLICTS_WITH` fields. For each conflict:
- Compare evidence side by side
- If one subagent had more context (e.g. saw both sides of a split) → that one wins
- If equal evidence → escalate (Step 3.5)

#### 3.3 — Validate CLEAN results
For each subagent that returned CLEAN:
- Check METHODS_USED — did it actually run caller audit + value trace?
- Check EVIDENCE — are there actual grep commands with output?
- If CLEAN but no evidence → re-run that subagent with explicit instructions

#### 3.4 — Cross-subagent integration check
For findings that touch exports/imports across subagent boundaries:
- Verify the change is consistent on BOTH sides
- If subagent A found a renamed export but subagent B didn't check consumers → run targeted grep

#### 3.5 — Escalation protocol
When subagents contradict or evidence is ambiguous:
1. Re-run conflicting subagent with the other's findings as additional context
2. If still contradictory → spawn a tiebreaker subagent with both outputs
3. If tiebreaker fails → report both with confidence levels, let user decide

### Failure handling

**Bad output**: Subagent returns no findings and no CLEAN → re-run with explicit file list and `--verbose`
**Suspicious CLEAN**: CLEAN with no EVIDENCE commands → reject, re-run with mandatory grep/read output
**Timeout**: Subagent doesn't return in 5 min → kill, log "TIMEOUT", continue with others, note in Blind Spots

### Kiedy NIE paralelizowac

- scope <= 5 plikow — rob sekwencyjnie, overhead subagentow nie wart
- tryb QUICK — za malo krokow, nie ma co dzielic

## Zasady

1. NIE UFAJ SOBIE - zakladaj ze zrobiles blad. Szukaj go aktywnie.
2. NIE SPIESZ SIE - dokladnosc > szybkosc.
3. Compiler + linter to MINIMUM, nie MAKSIMUM - Krok 2-4 lapia to, czego kompilator nie widzi.
4. Konkretne wartosci > abstrakcyjne rozumowanie - "to powinno dzialac" to NIE weryfikacja. Trace z wartosciami.
5. Kolejnosc wsteczna - czytanie od konca lamie pattern recognition.
6. Czytaj jak CUDZY kod - nie jak swoj. Swoj czytasz z intencja, cudzy z podejrzliwoscia.
7. Honest blind spots > falszywe "wszystko OK" - sekcja "czego NIE zweryfikowalem" to uczciwosc.
8. Literal output > verbal claim - "sprawdzilem, OK" BEZ $ komendy i outputu = NIE sprawdziles.
9. Freshness - czytaj pliki z dysku, nie z pamieci kontekstu.
10. Paralelizuj gdy scope > 5 plikow — subagenty per domena, orchestrator laczy raport.
11. **HANDLE FAILURES** — bad output, suspicious CLEAN, timeout to norma. Obsluz je, nie ignoruj.
12. **STRUCTURED OUTPUT** — kazdy subagent zwraca FINDING + EVIDENCE + SEVERITY + CONFLICTS_WITH. Bez prozy.
