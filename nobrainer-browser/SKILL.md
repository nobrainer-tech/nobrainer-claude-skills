---
name: nobrainer-browser
description: Cross-platform installer that bootstraps four browser-automation tools — Webwright (Microsoft browser-agent framework), Playwright MCP (Microsoft MCP server for browser control), the Playwright CLI test framework, and Vercel Labs' agent-browser — and wires the MCP server into both Claude Code (`~/.claude.json`) and Codex CLI (`~/.codex/config.toml`) atomically. Every npm install pins to a version that has been on the registry for at least 7 days (supply-chain cooldown). Stdlib-only Python 3.10+, no personal data, runs on macOS, Windows, and Linux.
---

# nobrainer-browser

Single-purpose skill: get four browser-automation tools installed and wired so
that BOTH Claude Code and Codex CLI can drive a browser. Same conventions as
`nobrainer-paperclip-setup`: stdlib-only, cross-platform paths, atomic writes,
no personal data, designed to be published publicly.

## Triggers

Activate when the user says:

- `nobrainer-browser`, "install browser tools", "set up browser automation"
- "install playwright mcp", "wire playwright mcp", "playwright mcp for claude"
- "install webwright", "install agent-browser"
- PL: "zainstaluj playwright mcp", "skonfiguruj browsery dla AI",
  "zainstaluj narzedzia do automatyzacji przegladarki"

## What it does

1. Detects what is already installed (Node, npm, pip, each of the four tools,
   and the wiring state of Claude/Codex config files).
2. Installs each tool through its native channel:
   - **Webwright**: two modes.
     - `marketplace` (default, recommended): no clone, no pip, no playwright
       download. The host's plugin loader fetches `microsoft/Webwright` from
       GitHub. Supports `claude` and `codex` hosts only.
     - `source` (opt-in via `--mode source`): `git clone` into a
       skill-managed directory, `pip install --user -e <clone>`, then
       `python -m playwright install chromium`. Required for `openclaw` and
       `hermes` hosts.
     Hosts: `claude`, `codex`, `openclaw`, `hermes` (select via
     `--hosts a,b,c`; default `claude,codex`). For Claude the skill prints
     the slash commands the user must run; for Codex/OpenClaw it shells out;
     for Hermes it creates a symlink under `~/.hermes/skills/webwright`.
   - **Playwright MCP**: no global install; resolves a 7-day-safe version via
     `npm view @playwright/mcp time --json`, caches the pin under
     `state.json`, and exposes it for wiring.
   - **Playwright CLI**: `npm install -g playwright@latest` followed
     by `playwright install` (Chromium + Firefox + WebKit). On Linux,
     `--with-deps` is supported via a flag.
   - **agent-browser**: `npm install -g agent-browser@<safe-version>` by
     default (also supports `--method=cargo` and `--method=brew`), then
     `agent-browser install` for Chrome for Testing, then
     `npx skills add vercel-labs/agent-browser` for the discovery stub.
3. Wires the Playwright MCP server into both editors:
   - Claude: tries `claude mcp add playwright npx "@playwright/mcp@<pin>"`;
     falls back to an atomic edit of `~/.claude.json` (`mcpServers.playwright`).
   - Codex: tries `codex mcp add playwright npx "@playwright/mcp@<pin>"`;
     falls back to a conservative splice of `[mcp_servers.playwright]` into
     `~/.codex/config.toml` that preserves every other section.
4. Verifies. Each tool exposes a `--version` probe; the MCP wiring is
   verified by reading the config files back.

## Architecture

```
nobrainer-browser/
|- SKILL.md
|- README.md
|- pyproject.toml
`- nobrainer_browser/
   |- __init__.py
   |- __main__.py            # argparse + dispatch (detect/install/wire/unwire/verify/status)
   |- paths.py               # cross-platform user/data/log dirs + atomic writes
   |- npm_safe.py            # 7-day npm registry cooldown (resolve + install + npx)
   |- detect.py              # host + per-tool + wiring snapshot
   |- verify.py              # health checks
   |- tools/
   |  |- webwright.py        # git clone + pip install -e + playwright install chromium
   |  |- playwright_mcp.py   # resolve + cache safe version (no global install)
   |  |- playwright_cli.py   # npm_safe.install_global + playwright install
   |  `- agent_browser.py    # npm/cargo/brew + agent-browser install + skills add
   `- wire/
      |- claude.py           # `claude mcp add` + ~/.claude.json fallback
      `- codex.py            # `codex mcp add` + ~/.codex/config.toml fallback
```

## CLI surface

| Command | Purpose |
| --- | --- |
| `python -m nobrainer_browser` | First-run banner + host snapshot. |
| `python -m nobrainer_browser detect [--json]` | Print host + tools + wiring as JSON. |
| `python -m nobrainer_browser install all [--cooldown-days N]` | Install all four tools. |
| `python -m nobrainer_browser install {webwright,playwright-mcp,playwright-cli,agent-browser}` | Install one tool. Add `--method={npm,cargo,brew}` for agent-browser; `--with-deps` on Linux. Webwright: `--mode={marketplace,source}` and `--hosts=claude,codex,openclaw,hermes`. |
| `python -m nobrainer_browser tool-uninstall webwright [--hosts ...] [--purge-source]` | Remove Webwright registration from hosts; optionally delete the source clone. |
| `python -m nobrainer_browser wire {claude,codex,both} [--tool playwright-mcp]` | Register Playwright MCP. |
| `python -m nobrainer_browser unwire {claude,codex,both} [--tool playwright-mcp]` | Remove the MCP entry. |
| `python -m nobrainer_browser verify [--tool ...]` | Run health checks. |
| `python -m nobrainer_browser status` | detect + verify + state.json dump. |

## Tool-to-editor wiring

| Tool | Installed via | Claude integration | Codex integration |
| --- | --- | --- | --- |
| Webwright (marketplace, default) | Host plugin loader fetches `microsoft/Webwright` | `/plugin marketplace add microsoft/Webwright` + `/plugin install webwright@webwright` (user types these) | `codex plugin marketplace add microsoft/Webwright` (skill shells out) |
| Webwright (source, opt-in) | `git clone` + `pip install --user -e` + `playwright install chromium` | `/plugin marketplace add <clone>` + `/plugin install webwright@webwright` | `codex plugin marketplace add <clone>` |
| Playwright MCP | npx on demand (safe-version pin cached) | `claude mcp add playwright npx "@playwright/mcp@<pin>"` or atomic edit of `~/.claude.json` | `codex mcp add playwright ...` or atomic splice into `~/.codex/config.toml` |
| Playwright CLI | `npm install -g playwright@latest` + `playwright install` | shell out via `npx playwright codegen`, `playwright test` | same |
| agent-browser | `npm install -g agent-browser@<safe-version>` (default); `cargo install` / `brew install` opt-in; then `agent-browser install` + `npx skills add vercel-labs/agent-browser` | binary on PATH, called directly | binary on PATH, called directly |

### Webwright supported hosts

Webwright can be registered with four host environments. The marketplace mode
is the default and works without any local checkout; the source mode is
required for hosts that only accept a local path.

| Host | Marketplace mode | Source mode | Install method |
| --- | --- | --- | --- |
| Claude Code | yes | yes | Two slash commands the user must paste. |
| Codex CLI | yes | yes | `codex plugin marketplace add <spec-or-path>` (skill shells out). |
| OpenClaw | no | yes only | `openclaw plugins install <path>` + `openclaw gateway restart`. |
| Hermes Agent | no | yes only | Symlink `~/.hermes/skills/webwright` -> `<clone>/skills/webwright`. |

## Security model

- **Supply-chain cooldown.** Every npm install resolves to the latest version
  published >= 7 days ago. `NPM_SAFE_BYPASS=1` disables the cooldown for the
  current process and emits a loud stderr warning. The cutoff defaults to
  7 days; override with `--cooldown-days`.
- **Atomic writes.** All config-file edits go via `tempfile.mkstemp` in the
  destination directory + `replace`, with Windows-aware retry on
  `PermissionError`. No partial writes.
- **No secret logging.** API keys are detected (truthy/falsy) but never
  printed, persisted, or written to logs.
- **No personal data.** The package contains no usernames, emails, hostnames,
  or company-specific paths. Safe to publish publicly.
- **Shell-free subprocess.** Every external invocation uses `shell=False` and
  resolves the executable via `shutil.which` before running.

## For LLMs

Invoke this skill when:

- The user asks to set up browser automation for an AI agent.
- The user mentions Playwright MCP, Webwright, or agent-browser by name.
- Either Claude Code or Codex CLI needs to gain browser control and the
  current config files don't already list a Playwright MCP server.

Do NOT invoke for:

- Running an existing Playwright test suite (that's the test runner, not
  this skill).
- Day-to-day browsing actions performed through an already-wired MCP server.
- Cleaning up test data inside a specific web app (use the appropriate
  domain skill instead).

## Requirements

- Python 3.10+
- Node.js >= 20 (for npm/npx)
- git (for Webwright clone)
- macOS, Windows 10+, or any modern Linux

Optional:
- Rust toolchain (`cargo`) if using `--method=cargo` for agent-browser.
- Homebrew (`brew`) if using `--method=brew` for agent-browser.
- One of `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY` for
  Webwright runtime.
