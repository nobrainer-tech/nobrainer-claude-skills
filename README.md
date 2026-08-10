# nobrainer-claude-skills

A collection of [Claude Code](https://claude.ai/code) skills I build and use daily. Publishing them here so others can benefit too.

Personal repo — I'm the sole maintainer. Grab anything useful; open an issue for bugs or ideas.

Each skill is a directory with a `SKILL.md` (YAML frontmatter `name` + `description` carrying its triggers). Claude Code auto-loads a skill when your request matches its description, or invoke it by name (`/skill-name`).

## Skills (24)

### Knowledge — LLM wiki (Karpathy pattern)

| Skill | What it does | Trigger |
|-------|--------------|---------|
| [llm-wiki](./llm-wiki/) | Set up a compounding personal knowledge base as an "LLM wiki" — 3-layer model (sources / curated pages / index+log+inbox), page conventions, git sync, bootstrap templates. Setup + methodology; entry point for `wiki-get`/`wiki-add`/`wiki-tidy`. | "llm wiki", "set up llm wiki", "wiki setup" |
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
| [playwright-cli](./playwright-cli/) | Latest Playwright from the CLI — agent `@playwright/cli` (attach to an existing logged-in browser over CDP, snapshot/click/eval, tracing) + classic test CLI (codegen, trace viewer `show-trace`, UI mode). Reads traces, binds to live sessions, macOS/Windows/WSL. | "playwright cli", "read trace", "attach to my browser" |
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

### [agents-restraint](./agents-restraint/)

Eight engineering rules for a repo's `CLAUDE.md` and `AGENTS.md` that stop a coding agent from over-building. The expensive failure mode in AI-written code isn't wrong code — it's *too much* code: three dependencies and five abstraction layers for what the standard library does in ten lines.

**Trigger:** "agents-restraint", "add the engineering rules", "stop the agent over-engineering", "AGENTS.md rules", "dodaj zasady inzynierskie"

**Two ways in:**
- **Repo already has agent instructions** → `assets/block.md`, the rules only, wrapped in markers so it can be re-applied
- **Repo has nothing yet** → `assets/template-AGENTS.md`, a full starting file: engineering rules, design principles (YAGNI/KISS/DRY/SOLID), comment discipline, configuration and secrets, subagent delegation, verification before done

**What it does:**
- Inserts into **both** `CLAUDE.md` and `AGENTS.md` — Cursor, Claude Code, Codex and Windsurf all read `AGENTS.md` from the repo root automatically
- Idempotent via `<!-- ENG-RULES:START -->` / `<!-- ENG-RULES:END -->` HTML-comment markers — applying it twice replaces rather than duplicates
- Leaves managed blocks from other tools (e.g. `pane-agent-context`) untouched
- Surfaces contradictions with existing rules instead of silently dropping one side

Origin: a Vercel Next.js engineer reportedly spent ~60B tokens iterating on an `AGENTS.md`; what survived compresses to these eight. Ships with a warning that rule 1 ("delete obsolete paths, no fallbacks, no migrations") is right for a web product with one deploy target and dangerous in anything holding state or money.

**The template is deliberately over budget, and says so.** Every line in these files is loaded into *every* prompt in the repo, relevant or not — a bloated `AGENTS.md` has the agent weighing git conventions while fixing a CSS bug. Karpathy's widely-copied `CLAUDE.md` is 65 lines; the template ships longer on purpose as a menu to cut from, not a finished file to paste whole.

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
