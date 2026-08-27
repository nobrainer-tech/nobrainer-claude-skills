---
name: codex-in-claude-code
description: "Use OpenAI Codex from inside Claude Code through the explicit /codex:review, /codex:rescue, or /codex:adversarial-review bridge commands, or install and diagnose that bridge. Use deep-autoreview for a generic closeout or second-model review request."
---

# Codex in Claude Code

Plugin oficjalny OpenAI: `openai/codex-plugin-cc`
Repo: https://github.com/openai/codex-plugin-cc

Pozwala wywołać Codex bezpośrednio z Claude Code — review kodu, adversarial review i delegowanie tasków do Codexa jako background job.

---

## Wymagania

- **ChatGPT subscription (w tym Free) lub OpenAI API key** — plugin używa lokalnego CLI Codex
- **Node.js 18.18+**
- **Codex CLI** (`@openai/codex`) zainstalowany globalnie

---

## Instalacja (jednorazowo)

**WAZNE:** Te `/plugin*` komendy **musi wpisac uzytkownik w prompt** (nie wolaj ich z Bash, nie pisz `/plugin ...` jako komendy do siebie). Claude **nie moze zainstalowac plugina sam** — to akcja po stronie harnessu.

**Pelna sekwencja (4 kroki, KAZDY w osobnym promptcie):**

```
/plugin marketplace add openai/codex-plugin-cc
/plugin install codex@openai-codex
/reload-plugins
/codex:setup
```

**Kolejnosc jest obowiazkowa.** Jezeli pominiesz `marketplace add`, krok `/plugin install codex@openai-codex` zwroci `not found` (marketplace `openai-codex` jeszcze nie istnieje w lokalnym registry).

Po `marketplace add` zobaczysz: `Successfully added marketplace: openai-codex`.
Po `install` zobaczysz: `✓ Installed codex. Run /reload-plugins to apply.`

Jesli Codex CLI nie jest zainstalowany:
```bash
npm install -g @openai/codex
```

Logowanie (mozna tez przez `!codex login` w Claude Code):
```bash
codex login
```

**Weryfikacja po instalacji:**
- `cat ~/.claude/plugins/installed_plugins.json | python3 -c "import json,sys;print('codex' in json.load(sys.stdin)['plugins'])"` → `True`
- W nowej sesji slash commands `/codex:review`, `/codex:adversarial-review`, `/codex:rescue` powinny byc dostepne

---

## Slash Commands

### `/codex:review [--wait|--background] [--base <ref>]`
Standardowy review kodu. Używa WC jako reviewer, taki sam jak `/review` w Codexie.

```bash
/codex:review                    # working tree (zapyta: foreground/background)
/codex:review --base main        # diff branch vs main
/codex:review --background       # od razu w tle
/codex:review --wait             # od razu foreground
```

Read-only — nie zmienia kodu.

---

### `/codex:adversarial-review [--wait|--background] [--base <ref>] [focus...]`
Review **kwestionujący** decyzje projektowe, nie tylko błędy. Pytania o tradeoffs, założenia, alternatywne podejścia, failure modes.

```bash
/codex:adversarial-review
/codex:adversarial-review --base main challenge whether caching approach is right
/codex:adversarial-review --background look for race conditions
```

Przyjmuje dodatkowy tekst jako focus area (w odróżnieniu od `/codex:review`).

---

### `/codex:rescue [--background|--wait] [--resume|--fresh] [--model <model>] [--effort <level>] <task>`
Deleguje task do Codexa. Codex może diagnozować bugi, pisać fixy, kontynuować poprzedni run.

```bash
/codex:rescue investigate why tests are failing
/codex:rescue fix the failing test with the smallest safe patch
/codex:rescue --resume apply the top fix from the last run
/codex:rescue --model gpt-5.4-mini --effort medium investigate flaky test
/codex:rescue --model spark fix it quickly
/codex:rescue --background investigate the regression
```

Modele: domyślny Codex, `gpt-5.4-mini`, `spark` (alias na `gpt-5.3-codex-spark`)
Effort levels: `none`, `minimal`, `low`, `medium`, `high`, `xhigh`

---

### `/codex:status [job-id]`
Pokazuje aktywne i ostatnie joby Codexa dla bieżącego repo.

```bash
/codex:status
/codex:status task-abc123
```

---

### `/codex:result [job-id]`
Pokazuje finalny output zakończonego joba. Zawiera też session ID do wznowienia w Codexie.

```bash
/codex:result
/codex:result task-abc123
```

---

### `/codex:cancel [job-id]`
Anuluje aktywny background job.

```bash
/codex:cancel
/codex:cancel task-abc123
```

---

### `/codex:setup [--enable-review-gate|--disable-review-gate]`
Sprawdza czy Codex jest gotowy. Opcjonalnie włącza/wyłącza review gate (Stop hook).

```bash
/codex:setup
/codex:setup --enable-review-gate
/codex:setup --disable-review-gate
```

**Uwaga**: review gate uruchamia Codex review przy każdym Stop — może szybko zużyć limity.

---

## Typowe Flow

### Review przed PR
```bash
/codex:review --base main
```

### Delegowanie buga do Codexa
```bash
/codex:rescue investigate why the build is failing in CI
```

### Długi task w tle
```bash
/codex:rescue --background investigate the flaky integration test
# ... pracuj dalej ...
/codex:status
/codex:result
```

### Adversarial review przed shipmentem
```bash
/codex:adversarial-review --base main challenge the auth and session design
```

---

## Konfiguracja Codexa

`~/.codex/config.toml` (user-level) lub `.codex/config.toml` (project-level):

```toml
model = "gpt-5.4-mini"
model_reasoning_effort = "xhigh"
```

Plugin używa tych samych ustawień co lokalne CLI Codex.

---

## Wznawianie w Codexie

Po `/codex:result` dostajesz session ID — możesz kontynuować pracę bezpośrednio w Codexie:
```bash
codex resume <session-id>
# lub
codex resume  # wybierz z listy
```
