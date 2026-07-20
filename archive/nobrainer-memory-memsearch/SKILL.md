---
name: nobrainer-memory
description: Install memsearch persistent memory for Claude Code. Auto-captures every session as markdown notes, injects relevant context on every prompt. Uses local Ollama embeddings (nomic-embed-text) — no API key needed. Use when setting up a new machine or when user says "install memory", "setup memsearch", "nobrainer-memory", "dodaj pamiec do claude", "zainstaluj memory".
---

# NoBrainer Memory — memsearch Installer

Installs memsearch persistent memory plugin for Claude Code.
Philosophy: Markdown is the source of truth. Vector index is just a cache.
Every session gets summarized into `.md` files. Semantic search injects relevant context automatically.

## What Gets Installed

1. `memsearch` Python CLI (PyPI)
2. `nomic-embed-text` Ollama model — local embeddings, no API key needed
3. memsearch ccplugin registered in Claude Code plugins
4. Config: `~/.memsearch/config.toml` (provider: ollama)

Memory files land in: `~/.memsearch/memory/YYYY-MM-DD.md` (global, all projects)

## Step 0 — Ask about memory scope

Before installing, ask the user:

> **Gdzie zapisywać memory?**
> 1. **Global** (`~/.memsearch/memory/`) — jeden pool dla wszystkich projektów. Działa gdy zawsze otwierasz Claude z `~`. Kontekst z różnych projektów miesza się w jednych plikach, ale semantic search i tak znajdzie właściwy.
> 2. **Per-projekt** (`<project-dir>/.memsearch/memory/`) — izolowana pamięć per repo. Wymaga otwierania Claude z folderu projektu (`cd ~/Github/mój-projekt && claude`).
>
> Który tryb preferujesz? (1 = global, 2 = per-projekt)

Based on the answer:
- **Global** → proceed with default install, `MEMORY_BASE=$HOME/.memsearch`
- **Per-projekt** → ask which directory: `W jakim folderze projektu?` → set `MEMORY_BASE=<project-dir>/.memsearch`, note it in the summary

Store the choice in `MEMORY_SCOPE` variable for use in Step 8 summary.

## Step 1 — Detect environment

```bash
python3 --version
which pip3 || which pip
which ollama || echo "OLLAMA_MISSING"
uname -s  # Darwin or Linux
```

If Ollama is missing:
- macOS: `brew install ollama` (if brew available) or instruct user to install from https://ollama.com
- Linux: `curl -fsSL https://ollama.com/install.sh | sh`
- If Ollama cannot be installed automatically, configure memsearch with `openai` provider instead (requires `OPENAI_API_KEY`)

## Step 2 — Install memsearch CLI

Try in order until one succeeds:

```bash
# Option A: pip3 (preferred)
pip3 install memsearch

# Option B: if A fails with "externally-managed-environment" (macOS Homebrew Python)
pip3 install memsearch --break-system-packages

# Option C: pipx
pipx install memsearch

# Option D: uv
uv tool install memsearch
```

Verify: `memsearch --version`

## Step 3 — Pull embedding model

```bash
# Start ollama server if not running (macOS)
# ollama is usually auto-started as a service

ollama pull nomic-embed-text
```

Verify: `ollama list | grep nomic-embed-text`

If Ollama unavailable, skip to Step 4 and set provider to `openai`.

## Step 4 — Configure memsearch

```bash
memsearch config set embedding.provider ollama
memsearch config set embedding.model nomic-embed-text
```

If using OpenAI fallback:
```bash
memsearch config set embedding.provider openai
memsearch config set embedding.model text-embedding-3-small
# User must have OPENAI_API_KEY in their env
```

Verify: `cat ~/.memsearch/config.toml`

## Step 5 — Install Claude Code plugin

### Option A: Marketplace (preferred, simplest)

Use the Claude Code built-in marketplace commands:

```bash
# From Claude Code CLI:
marketplace add zilliztech/memsearch

# Or equivalently:
/plugin install memsearch
```

This handles downloading, registering, and configuring the plugin automatically.

Full docs: https://zilliztech.github.io/memsearch/claude-plugin/

### Option B: Manual install (fallback if marketplace unavailable)

Check Claude Code plugins directory exists:
```bash
ls ~/.claude/plugins/installed_plugins.json
```

If it doesn't exist, Claude Code is not installed — tell the user to install Claude Code first.

Clone memsearch repo and copy plugin files:
```bash
TMPDIR=$(mktemp -d)
git clone --depth=1 https://github.com/zilliztech/memsearch.git "$TMPDIR/memsearch"

PLUGIN_VERSION=$(memsearch --version | sed 's/memsearch, version //')
PLUGIN_DIR="$HOME/.claude/plugins/cache/zilliztech/memsearch/$PLUGIN_VERSION"

mkdir -p "$PLUGIN_DIR/hooks" "$PLUGIN_DIR/skills/memory-recall" "$PLUGIN_DIR/scripts"
cp "$TMPDIR/memsearch/ccplugin/hooks/"* "$PLUGIN_DIR/hooks/"
cp "$TMPDIR/memsearch/ccplugin/scripts/"* "$PLUGIN_DIR/scripts/"
cp "$TMPDIR/memsearch/ccplugin/skills/memory-recall/"* "$PLUGIN_DIR/skills/memory-recall/"

rm -rf "$TMPDIR"
```

## Step 6 — Register plugin (only for Option B manual install)

Skip this step if you used marketplace install (Option A) — it registers automatically.

Read `~/.claude/plugins/installed_plugins.json`.

Check if `memsearch@zilliztech` already exists in the `plugins` object. If yes — update `installPath` and `version`. If no — add a new entry.

Add/update this entry in the `plugins` object (before the closing `}`):

```json
"memsearch@zilliztech": [
  {
    "scope": "user",
    "installPath": "/Users/<USERNAME>/.claude/plugins/cache/zilliztech/memsearch/<VERSION>",
    "version": "<VERSION>",
    "installedAt": "<ISO_TIMESTAMP>",
    "lastUpdated": "<ISO_TIMESTAMP>"
  }
]
```

Replace `<USERNAME>` with `$HOME` resolved, `<VERSION>` with actual memsearch version, `<ISO_TIMESTAMP>` with current UTC time in ISO 8601 format.

**IMPORTANT:** Use Edit tool (not Write) to update the JSON. Preserve all existing plugin entries.

## Step 7 — Verify installation

```bash
echo "=== memsearch ===" && memsearch --version
echo "=== config ===" && cat ~/.memsearch/config.toml
echo "=== ollama ===" && ollama list | grep nomic
echo "=== plugin ===" && ls ~/.claude/plugins/cache/zilliztech/memsearch/
```

All four checks should pass.

## Step 8 — Initialize auto memory for current project

Claude Code has a built-in **auto memory** system (separate from memsearch) at:
`~/.claude/projects/<project-hash>/memory/MEMORY.md`

This file is automatically loaded into every conversation context for that project.

If the user is running this skill from within a project directory:

1. Detect the project memory path from the system prompt (look for "persistent auto memory directory at")
2. Create the `memory/` directory if it doesn't exist
3. Create `MEMORY.md` with a basic template:

```markdown
# Project Auto Memory

## Key Facts
- (add project-specific facts here)

## Conventions
- (add coding conventions, preferences)

## Detailed Topics
See `~/.memsearch/memory/` for semantic search memory.
```

4. Tell the user: "Auto memory initialized. Edit `MEMORY.md` to add project-specific context that should always be available."

## Step 9 — Report to user

Print a summary:
```
memsearch installed successfully.

Version: <version>
Embeddings: ollama/nomic-embed-text (local, no API key needed)
Memory files: ~/.memsearch/memory/YYYY-MM-DD.md
Plugin: registered in Claude Code
Auto memory: <project memory path>/MEMORY.md (always loaded)

Restart Claude Code to activate. From next session:
  SessionStart  — injects last 2 days of notes as context
  Every prompt  — semantic search injects top-3 relevant memories
  Session end   — Claude Haiku summarizes session to .md
  Always        — MEMORY.md loaded into context (project-specific)
```

## Error Handling

| Problem | Fix |
|---------|-----|
| pip not found | Try pip3, pipx, uv in order |
| externally-managed-environment | Add `--break-system-packages` |
| Ollama not installed | Install via brew/curl or fall back to openai provider |
| ollama pull fails (no internet) | Use `local` provider: `memsearch config set embedding.provider local` |
| installed_plugins.json malformed | Read it, fix JSON, then edit |
| git not found | Download zip: `curl -L https://github.com/zilliztech/memsearch/archive/main.zip -o /tmp/ms.zip && unzip /tmp/ms.zip -d /tmp/ms-extracted` |

## Notes

- Memory is global (all projects share `~/.memsearch/memory/`) when Claude Code is launched from `~`
- If user always opens Claude Code from a specific project folder, memory will be per-project in `<project>/.memsearch/memory/`
- Haiku summarization uses the `claude` CLI — no extra setup needed if Claude Code is installed
- Milvus-lite (local .db) is the default backend — no Milvus server needed
- Watch process is skipped in lite mode — indexing happens once at SessionStart
