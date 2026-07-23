# nobrainer-claude-skills

A collection of [Claude Code](https://claude.ai/code) skills I build and use daily. Publishing them here so others can benefit too.

Personal repo — I'm the sole maintainer. Grab anything useful; open an issue for bugs or ideas.

Each skill is a directory with a `SKILL.md` (YAML frontmatter `name` + `description` carrying its triggers). Claude Code auto-loads a skill when your request matches its description, or invoke it by name (`/skill-name`).

## Skills (23)

### Knowledge — LLM wiki (Karpathy pattern)

| Skill | What it does | Trigger |
|-------|--------------|---------|
| [karpathy-llm-wiki](./karpathy-llm-wiki/) | Set up a compounding personal knowledge base as an "LLM wiki" — 3-layer model (sources / curated pages / index+log+inbox), page conventions, git sync, bootstrap templates. Setup + methodology. | "set up llm wiki", "wiki setup" |
| [wiki-add](./wiki-add/) | Ingest a source (URL/PDF/notes) or promote the inbox into the wiki — synthesize into interlinked pages, update `index.md`/`log.md`. | "wiki-add", "save this to the wiki" |
| [wiki-get](./wiki-get/) | Query the wiki — navigate the index, grep pages, answer with citations. | "wiki-get", "ask the wiki" |
| [wiki-tidy](./wiki-tidy/) | Lint the wiki — orphans, dead links, contradictions, stale claims; promote pending inbox items. | "wiki-tidy", "lint wiki" |
| [nobrainer-memory](./nobrainer-memory/) | Install the whole wiki-memory system in an Obsidian git vault, wired into every AI client via always-on instructions; auto-captures durable facts to a per-machine inbox. | "install memory", "nobrainer-memory" |

### Multi-agent orchestration & autonomy

| Skill | What it does | Trigger |
|-------|--------------|---------|
| [nobrainer-ultracode-workflow](./nobrainer-ultracode-workflow/) | Cost-disciplined "ultracode" multi-agent Workflow — orchestration steered by the top model, agents on cheaper tiers, a compact quality directive per agent. Includes a tier picker + calibration recipe. | "ultracode workflow", "fan out" |
| [nobrainer-team-builder](./nobrainer-team-builder/) | Assemble a team of expert subagents on-demand from a catalog of **401 agents / 27 categories** — nothing loaded into context until picked. | "nbteam", "team builder" |
| [nobrainer-autopilot](./nobrainer-autopilot/) | Autonomous CI/CD loop — collects work items, spawns teams, implements on branches, opens PRs, drives a **fail-closed Copilot review gate**, and (only when explicitly armed) merges/deploys. Language-agnostic. | "autopilot", "autonomous mode" |
| [karpathy-auto-improver](./karpathy-auto-improver/) | Score-driven autonomous improvement loop for any artifact (SKILL.md, prompt, checklist) — rubric → baseline → diverse variants → judge panel → graft → repeat until plateau. | "auto improve", "autoresearch" |

### Code review & quality

| Skill | What it does | Trigger |
|-------|--------------|---------|
| [deep-audit](./deep-audit/) | Evidence-based post-implementation verification — backward line-by-line review, value traces, caller audits with shown grep output. Any language. | after a feature/fix, before committing |
| [deep-autoreview](./deep-autoreview/) | Structured closeout code review (Codex default, Claude optional) on a diff/commit/PR; verifies every finding against the real code path. | "deep autoreview", "codex review" |
| [deep-bugs-finder](./deep-bugs-finder/) | Adversarially hunt for real bugs and write each verified one to a `bugs/` folder with a fix; loops until dry. | "find bugs", "bug hunt" |
| [deep-rca](./deep-rca/) | Root-cause analysis with 10 parallel agents — traces code paths, logs, API calls; every claim backed by evidence. | "deep rca", "root cause" |

### Security

| Skill | What it does | Trigger |
|-------|--------------|---------|
| [nobrainer-fast-audit](./nobrainer-fast-audit/) | Universal security diagnostic — system posture, vet a skill/plugin before install, IOC scan, OWASP Agentic Top 10 hardening. macOS/Linux/Windows/VPS. | `/safety-audit`, `/safety-check-skill`, `/safety-scan` |
| [nobrainer-npm-secure](./nobrainer-npm-secure/) | Harden against npm supply-chain attacks — minimum-release-age cooldown across npm/pnpm/bun, block lifecycle scripts, pin deps, commit lockfile. | "secure npm", "npm supply chain" |

### Browser automation

| Skill | What it does | Trigger |
|-------|--------------|---------|
| [agent-browser](./agent-browser/) | Drive Vercel's `agent-browser` — Rust CLI for AI browser automation via CDP with deterministic ref selectors and JSON output. | "agent-browser", "automate browser" |
| [nobrainer-browser](./nobrainer-browser/) | Cross-platform installer that bootstraps four browser-automation tools (Webwright, Playwright MCP, Playwright CLI, agent-browser) and wires the MCP server into Claude Code + Codex. | "install browser tools" |

### Tooling & integrations

| Skill | What it does | Trigger |
|-------|--------------|---------|
| [claude-fable](./claude-fable/) | Launch Claude Code with a community-leaked "Claude Fable 5" system prompt. **Enables `--dangerously-skip-permissions`** — read the skill's caveats first. | "claude fable", "/claude-fable" |
| [codex-in-claude-code](./codex-in-claude-code/) | Use OpenAI Codex from inside Claude Code — code reviews, adversarial reviews, task delegation via the official Codex plugin. | "/codex:review", "delegate to Codex" |
| [pane](./pane/) | Install and drive RunPane — keyboard-first desktop manager for running multiple terminal AI agents in parallel, each in its own git worktree. | "pane", "runpane" |
| [nobrainer-reddit](./nobrainer-reddit/) | Reddit CLI — read posts, search subreddits, comment, manage your account via PRAW + OAuth2. Personal, non-commercial. | "reddit", "search subreddit" |

### Project setup

| Skill | What it does | Trigger |
|-------|--------------|---------|
| [nobrainer-starter](./nobrainer-starter/) | Bootstrap a project — create `AGENTS.md` + `CLAUDE.md` (identical content) with engineering standards, workflow rules, safety rules; scaffold `tasks/`. Merge-safe. | "setup project", "bootstrap standards" |
| [nobrainer-continuous-improvement](./nobrainer-continuous-improvement/) | Upgrade an existing project's `CLAUDE.md` with proven workflow/task/core-principle rules — adds only missing sections, never overwrites. | "continuous improvement", "upgrade CLAUDE.md" |

## Installation

Each skill is self-contained. Copy or symlink a skill directory into `~/.claude/skills/`:

```bash
git clone https://github.com/nobrainer-tech/nobrainer-claude-skills.git
cd nobrainer-claude-skills

# copy one skill
cp -r deep-audit ~/.claude/skills/

# or symlink it (auto-updates on git pull)
ln -s "$(pwd)/deep-audit" ~/.claude/skills/deep-audit
```

Then restart Claude Code — the skill loads on next session. Most skills also work with Codex/opencode if you point their skills dir at the same folder.

A few skills need a prerequisite (a CLI, an MCP server, or a plugin) or ship a companion note/scripts alongside `SKILL.md` — read the skill's own `SKILL.md` first.

## Contributing / conventions

See [AGENTS.md](./AGENTS.md) (and its twin [CLAUDE.md](./CLAUDE.md)) for how skills in this repo are structured — frontmatter, triggers, and the public-clean rules (no secrets, no machine-specific paths, no private client names).

## License

MIT © 2026 Arkadiusz Mastalerz (nobrainer-tech)
