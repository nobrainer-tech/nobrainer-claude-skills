---
name: claude-fable
description: Set up and launch Claude Code with a community-leaked "Claude Fable 5" system prompt plus --dangerously-skip-permissions. Use when the user types /claude-fable, says "claude fable", "odpal fable", "uruchom fable", or wants to start a Claude session running the leaked Fable 5 system prompt.
---

# claude-fable

Launches Claude Code with a leaked **Claude Fable 5** system prompt applied and
`--dangerously-skip-permissions` enabled.

## What this actually does (be honest with the user)

- It sets the system prompt of **whatever model Claude Code is already configured to run**.
  It does **not** swap the underlying model — there is no separate "Fable 5" you unlock by
  loading a file. It's a persona/behavior experiment, not a capability bump.
- The prompts are community leaks (NOT official Anthropic artifacts).

## Prompt variants (`CLAUDE_FABLE_VARIANT`)

- **`codecli`** (default) — the Claude **Code** agentic system prompt for Fable 5.
  Source: `asgeirtj/system_prompts_leaks` → `Anthropic/Claude Code/claude-code-2.1.172-fable-5.md`.
  Apples-to-apples replacement (keeps tool-use / software-engineering behavior). Stored as `CLAUDE-CODE-FABLE-5.md`.
- **`both`** — applies **both** prompts at once: the Claude Code agentic prompt as the base
  (`--system-prompt-file`) PLUS the consumer chat persona appended (`--append-system-prompt-file`).
- **`chat`** — only the consumer claude.ai Fable 5 chat prompt.
  Source: `elder-plinius/CL4R1T4S` → `ANTHROPIC/CLAUDE-FABLE-5.md`.
  Replacing the agent prompt with this strips coding-agent behavior (chat persona only). Stored as `CLAUDE-FABLE-5.md`.

`CLAUDE_FABLE_MODE=append` applies only to the single-prompt variants (`codecli`/`chat`); `both`
always uses replace-base + append.

## Files in this skill

- `CLAUDE-CODE-FABLE-5.md` — Claude Code agentic Fable 5 prompt (default variant).
- `CLAUDE-FABLE-5.md` — consumer chat Fable 5 prompt (`CLAUDE_FABLE_VARIANT=chat`).
- `bin/claude-fable` — the launcher. Downloads the selected variant on first use if missing,
  then `exec claude --dangerously-skip-permissions --system-prompt-file <variant>`.

## How to launch

An interactive Claude REPL cannot be started from inside a running Claude session/tool call.
So when this skill is invoked:

1. Ensure the launcher is installed and the selected prompt is present (see Setup). Confirm with
   a dry run: `CLAUDE_FABLE_DRYRUN=1 claude-fable`.
2. Tell the user to start the Fable session from a **terminal**:
   ```
   claude-fable                         # Claude Code Fable prompt (default)
   CLAUDE_FABLE_VARIANT=both claude-fable
   CLAUDE_FABLE_VARIANT=chat claude-fable
   ```
   (From inside Claude Code they can run `! claude-fable`, but it nests a second session.)

For a **one-shot, non-interactive** answer (CAN be run from a tool call):
```
claude-fable -p "your question here"
```

## Setup / repair (idempotent)

```bash
SK="$HOME/.claude/skills/claude-fable"
chmod +x "$SK/bin/claude-fable"
ln -sf "$SK/bin/claude-fable" /opt/homebrew/bin/claude-fable   # or ~/.local/bin
[ -s "$SK/CLAUDE-CODE-FABLE-5.md" ] || claude-fable --update
```

## Useful flags / env

- `claude-fable --update` — re-download the selected variant before launching.
- `CLAUDE_FABLE_VARIANT=codecli|chat` — choose which leaked prompt to apply (default `codecli`).
- `CLAUDE_FABLE_MODE=append claude-fable` — append the prompt instead of replacing.
- `CLAUDE_FABLE_DRYRUN=1 claude-fable` — print the exact command without running it.
- Any extra args pass through to `claude` (e.g. `claude-fable --model opus`).
