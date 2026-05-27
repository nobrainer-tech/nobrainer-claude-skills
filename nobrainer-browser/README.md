# nobrainer-browser

Cross-platform installer that bootstraps four browser-automation tools and
wires the Playwright MCP server into both Claude Code and Codex CLI with a
7-day npm supply-chain cooldown. Stdlib-only Python 3.10+.

## What you get

| Tool | What it is | Where it lands |
| --- | --- | --- |
| Webwright | Microsoft's Python framework for browser-driving agents. | Default: registered via host marketplace from `microsoft/Webwright` (no clone). Opt-in `--mode source` clones into `<data_dir>/webwright` and runs `pip install --user -e`. |
| Playwright MCP | Microsoft's MCP server exposing a browser as MCP tools. | Invoked on demand via `npx @playwright/mcp@<pin>`. Pin cached locally. |
| Playwright CLI | The Playwright test framework. | `npm install -g playwright@<pin>` + `playwright install`. |
| agent-browser | Vercel Labs' Rust CLI for headful agent browsing. | `npm install -g agent-browser@<pin>` + `agent-browser install` + Vercel skills stub. |

The MCP server is wired into both editors:

- **Claude Code**: prefers `claude mcp add ...`, falls back to atomic edit of
  `~/.claude.json`.
- **Codex CLI**: prefers `codex mcp add ...`, falls back to atomic splice of
  `[mcp_servers.playwright]` into `~/.codex/config.toml`. All other sections
  are preserved.

## Install

```bash
# From this skill directory
python3 -m pip install --user -e .

# Or just run via the module form (no install required if the package is on PYTHONPATH)
python3 -m nobrainer_browser --help
```

## One-shot setup

```bash
# Install everything (7-day cooldown applies to npm packages)
python3 -m nobrainer_browser install all

# Wire the MCP server into both editors
python3 -m nobrainer_browser wire both --tool playwright-mcp

# Verify
python3 -m nobrainer_browser verify
```

## Common commands

```bash
python3 -m nobrainer_browser detect              # JSON snapshot of host + tools + wiring
python3 -m nobrainer_browser install playwright-mcp
python3 -m nobrainer_browser install agent-browser --method=brew   # macOS/Linux
python3 -m nobrainer_browser install playwright-cli --with-deps    # Linux only
python3 -m nobrainer_browser wire claude --tool playwright-mcp
python3 -m nobrainer_browser unwire codex --tool playwright-mcp
python3 -m nobrainer_browser status
```

## Webwright install modes

Webwright supports two modes and four hosts (`claude`, `codex`, `openclaw`,
`hermes`). Default mode is `marketplace`; default hosts are `claude,codex`.

```bash
# Marketplace (recommended). No clone, no pip, no playwright download.
python3 -m nobrainer_browser install webwright
python3 -m nobrainer_browser install webwright --hosts claude
python3 -m nobrainer_browser install webwright --hosts codex

# Source mode. Clones microsoft/Webwright locally; required for openclaw + hermes.
python3 -m nobrainer_browser install webwright --mode source --hosts claude,codex,openclaw,hermes

# Remove webwright from chosen hosts (Claude requires a slash command from the user).
python3 -m nobrainer_browser tool-uninstall webwright --hosts hermes
python3 -m nobrainer_browser tool-uninstall webwright --hosts claude,codex,openclaw,hermes --purge-source
```

| Host | `marketplace` | `source` | How it lands |
| --- | --- | --- | --- |
| `claude` | yes | yes | Skill prints the two `/plugin ...` slash commands to paste. |
| `codex` | yes | yes | Shells out `codex plugin marketplace add ...`. |
| `openclaw` | no | yes only | `openclaw plugins install <clone>` + `openclaw gateway restart`. |
| `hermes` | no | yes only | Symlink `~/.hermes/skills/webwright` -> `<clone>/skills/webwright`. Windows requires Developer Mode or admin. |

## Where things land

- Config: `~/Library/Application Support/nobrainer-browser` (macOS),
  `%APPDATA%\nobrainer-browser` (Windows), `~/.config/nobrainer-browser`
  (Linux).
- Data (clones, caches): same root on macOS/Windows, `~/.local/share/nobrainer-browser`
  on Linux.
- Logs: `~/Library/Logs/nobrainer-browser` (macOS),
  `%LOCALAPPDATA%\nobrainer-browser\Logs` (Windows),
  `~/.local/state/nobrainer-browser/logs` (Linux).

## Supply-chain cooldown

Every npm install pins to the latest version published at least 7 days ago.
Override with `--cooldown-days N`. To bypass entirely (not recommended), set
`NPM_SAFE_BYPASS=1` — the skill will emit a loud stderr warning.

## Troubleshooting

**`npm not found in PATH (install Node >= 20)`** — install Node.js 20 or
newer. nvm: `nvm install --lts && nvm use --lts`.

**`claude CLI not found`** — the skill falls back to editing `~/.claude.json`
directly. Restart Claude Code after the edit to pick up the new MCP server.

**`codex CLI not found`** — same idea: the skill falls back to editing
`~/.codex/config.toml`. Restart Codex.

**Webwright "no API key" warning** — Webwright needs one of `OPENAI_API_KEY`,
`ANTHROPIC_API_KEY`, or `OPENROUTER_API_KEY` in the environment to run. The
install will complete; you just can't drive it until a key is set.

**Linux: Playwright complains about missing system libs** — re-run with
`--with-deps`, e.g. `python3 -m nobrainer_browser install playwright-cli
--with-deps`.

## Security

- No personal data in source or runtime output.
- All config-file edits are atomic (tempfile + replace).
- Subprocess calls use `shell=False` and `shutil.which` resolution.
- API keys are detected (presence-only), never logged or persisted.

## License

MIT.
