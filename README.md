# nobrainer-claude-skills

A collection of [Claude Code](https://claude.ai/code) skills that I build and use daily. Publishing them here so others can benefit too.

This is a personal repo — I'm the sole maintainer. If you find a skill useful, feel free to grab it. If you have ideas or find bugs, open an issue.

## Skills

### [nobrainer-fast-audit](./nobrainer-fast-audit/)

Universal security diagnostic skill for Claude Code. Cross-platform: macOS, Linux, Windows, VPS.

**Commands:**
- `/safety-audit` — Full system security audit (OS posture, agent config, credentials, network, processes)
- `/safety-check-skill <path>` — Vet a skill/plugin before installation (risk score 0-100)
- `/safety-scan` — Quick IOC scan (C2 connections, malware artifacts, suspicious processes)

**Covers:**
- macOS: SIP, Gatekeeper, FileVault, Firewall, XProtect, Launch Agents
- Linux: SELinux/AppArmor, UFW/iptables, LUKS, unattended upgrades, systemd
- Windows: Defender, UAC, BitLocker, Windows Firewall, SmartScreen
- VPS: SSH hardening, fail2ban, rootkit detection, open ports
- AI Agent Platforms: Claude Code, OpenClaw, and other agent frameworks
- OWASP Agentic Top 10 (2026) hardening guide (ASI01-ASI10)
- Known threats: ClawHavoc campaign, MCP server CVEs, supply chain patterns

### [nobrainer-polymarket](./nobrainer-polymarket/)

Interact with [Polymarket](https://polymarket.com) prediction markets via the official `polymarket-cli`. Browse markets, check prices, place orders, manage positions, and redeem winnings — all from the terminal.

**Use when:** searching markets, checking prices/order books, trading, viewing portfolios, redeeming won positions, or any Polymarket task via CLI.

**Includes:**
- Installation instructions (install script, manual download with checksum verification, build from source)
- Authentication setup (wallet import, config file, env vars, signature types)
- All workflows: market research, trading, order management, CTF redeem, leaderboard
- Full command reference in `references/commands.md`
- NegRisk vs standard market guidance (most binary markets are NegRisk)

### [nobrainer-team-builder](./nobrainer-team-builder/)

Dynamically assemble a team of expert subagents for any task from a catalog of **401 agents across 27 categories**. Agents are spawned on-demand as temporary subagents — zero permanent context cost.

**Trigger:** "nbteam", "team builder", "build team", "assemble team"

**How it works:**
1. Reads your task/request
2. Selects 2-5 relevant categories → loads only those category JSONs
3. Picks best 3-10 agents from loaded categories
4. Reads full agent `.md` only for selected agents
5. Spawns each as a temporary subagent via the Agent tool
6. Collects results and synthesizes a unified answer

**Categories include:** AI specialists, API/GraphQL, blockchain/Web3, data/AI, database, DevOps, security, programming languages (49 agents), development tools, documentation, and 17 more.

Agent definitions sourced from [davila7/claude-code-templates](https://github.com/davila7/claude-code-templates).

### [nobrainer-memory](./nobrainer-memory/)

Install persistent semantic memory for Claude Code using [memsearch](https://github.com/nicobailey/memsearch). Every session is auto-captured as markdown notes, with relevant context injected on every prompt via local Ollama embeddings — no API key needed.

**Trigger:** "install memory", "setup memsearch", "nobrainer-memory", "dodaj pamiec do claude"

**What gets installed:**
- `memsearch` Python CLI (PyPI)
- `nomic-embed-text` Ollama model — local embeddings
- memsearch ccplugin registered in Claude Code plugins
- Config: `~/.memsearch/config.toml`

Supports global (`~/.memsearch/memory/`) or per-project memory scope.

### [nobrainer-starter](./nobrainer-starter/)

Project bootstrapper — creates `AGENTS.md` and `CLAUDE.md` with engineering standards and workflow rules in any project directory.

**Commands:**
- `/nobrainer-starter` — Bootstrap current project with all standards
- or: "setup project", "init project", "create AGENTS.md", "bootstrap project standards"

Both files receive **identical content** — works with Claude Code, Codex, Kimi, Cursor, or any AI coding assistant that reads project config files.

**Creates:**
- `AGENTS.md` + `CLAUDE.md` — identical content covering:
  - Engineering principles: DRY, KISS, SOLID, YAGNI, Clean Code, error handling, testability, communication ethics (no docs unless asked, no emojis, single method approach)
  - Workflow rules: Plan Mode, Subagent Strategy, Verification Before Done, Task Management, Git Rules
  - Safety Rules: destructive commands (`rm -rf`, `DROP TABLE`, `git reset --hard`, force push, wiping directories) require explicit confirmation before execution
- `tasks/todo.md` — task tracker stub
- `tasks/lessons.md` — lessons log stub

Merge-safe: if files already exist, only missing sections are added — existing content is never overwritten.

## Installation

Copy any skill directory into `~/.claude/skills/`:

```bash
# Clone the repo
git clone https://github.com/nobrainer-tech/nobrainer-claude-skills.git

# Install a skill
cp -r nobrainer-claude-skills/nobrainer-fast-audit ~/.claude/skills/
cp -r nobrainer-claude-skills/nobrainer-starter ~/.claude/skills/
cp -r nobrainer-claude-skills/nobrainer-polymarket ~/.claude/skills/
cp -r nobrainer-claude-skills/nobrainer-team-builder ~/.claude/skills/
cp -r nobrainer-claude-skills/nobrainer-memory ~/.claude/skills/

# Or symlink (auto-updates with git pull)
ln -s "$(pwd)/nobrainer-claude-skills/nobrainer-fast-audit" ~/.claude/skills/nobrainer-fast-audit
ln -s "$(pwd)/nobrainer-claude-skills/nobrainer-starter" ~/.claude/skills/nobrainer-starter
ln -s "$(pwd)/nobrainer-claude-skills/nobrainer-polymarket" ~/.claude/skills/nobrainer-polymarket
ln -s "$(pwd)/nobrainer-claude-skills/nobrainer-team-builder" ~/.claude/skills/nobrainer-team-builder
ln -s "$(pwd)/nobrainer-claude-skills/nobrainer-memory" ~/.claude/skills/nobrainer-memory
```

Then restart Claude Code — the skill will be available immediately.

## License

MIT
