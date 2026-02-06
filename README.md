# nobrainer-claude-skills

Essential skills for [Claude Code](https://claude.ai/code) — security auditing, hardening guidance, and more.

## Skills

### [safety-first](./safety-first/)

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

## Installation

Copy any skill directory into `~/.claude/skills/`:

```bash
# Clone the repo
git clone https://github.com/nobrainer-tech/nobrainer-claude-skills.git

# Install a skill
cp -r nobrainer-claude-skills/safety-first ~/.claude/skills/

# Or symlink it (auto-updates with git pull)
ln -s "$(pwd)/nobrainer-claude-skills/safety-first" ~/.claude/skills/safety-first
```

Then restart Claude Code — the skill will be available immediately.

## License

MIT
