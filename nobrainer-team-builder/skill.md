# NoBrainer Team Builder

Dynamically assemble a team of expert subagents for any task from a catalog of 401 agents across 27 categories. Agents are spawned on-demand — nothing loaded into context until needed.

**Trigger**: "nbteam", "team builder", "build team", "nobrainer team", "use nbteam", "compose team", "agent team", "assemble team"

**Agent source**: All 401 agent definitions are sourced from [davila7/claude-code-templates](https://github.com/davila7/claude-code-templates) and ship with this skill — no setup or download needed.

## How It Works

This skill does NOT copy agents into the project. Instead, it:
1. Reads the task/request from the user
2. Identifies relevant categories → loads only those category JSONs from `categories/`
3. Picks best agents from loaded categories
4. Reads full agent `.md` only for selected agents from `agent-catalog/`
5. Spawns each as a **temporary subagent** via Agent tool

**Zero permanent context cost.** Only relevant categories are read, not all 401 agents.

## Directory Structure

```
~/.claude/skills/nobrainer-team-builder/
├── skill.md                          # This file
├── agent-catalog.json                # Full index (name → description + category)
├── categories/                       # Per-category JSON indexes
│   ├── ai-specialists.json           #   6 agents
│   ├── api-graphql.json              #   8 agents
│   ├── blockchain-web3.json          #   4 agents
│   ├── business-marketing.json       #  18 agents
│   ├── data-ai.json                  #  38 agents
│   ├── database.json                 #  11 agents
│   ├── deep-research-team.json       #  16 agents
│   ├── development-team.json         #  16 agents
│   ├── development-tools.json        #  30 agents
│   ├── devops-infrastructure.json    #  37 agents
│   ├── documentation.json            #  11 agents
│   ├── expert-advisors.json          #  52 agents
│   ├── ffmpeg-clip-team.json         #   8 agents
│   ├── finance.json                  #   5 agents
│   ├── game-development.json         #   5 agents
│   ├── git.json                      #   3 agents
│   ├── mcp-dev-team.json             #   8 agents
│   ├── modernization.json            #   3 agents
│   ├── obsidian-ops-team.json        #   7 agents
│   ├── ocr-extraction-team.json      #   7 agents
│   ├── performance-testing.json      #   5 agents
│   ├── podcast-creator-team.json     #  11 agents
│   ├── programming-languages.json    #  49 agents
│   ├── realtime.json                 #   2 agents
│   ├── security.json                 #  20 agents
│   ├── ui-analysis.json              #   5 agents
│   └── web-tools.json                #  16 agents
└── agent-catalog/                    # Full agent definitions (401 .md files)
    ├── ai-specialists/               #   6 agents
    │   ├── ai-ethics-advisor.md
    │   └── ...
    ├── programming-languages/        #  49 agents
    │   ├── python-pro.md
    │   ├── javascript-pro.md
    │   └── ...
    ├── security/                     #  20 agents
    │   ├── security-auditor.md
    │   └── ...
    └── ... (27 category folders total)
```

## Workflow

### Step 1: Understand the Task

Read the user's request. Identify:
- **What needs to be done** (code review? architecture? debugging? deployment?)
- **Technologies involved** (Python? React? Supabase? Terraform?)
- **Complexity** (single agent sufficient, or multi-agent collaboration needed?)

### Step 2: Select Categories

Based on the task, pick 2-5 **relevant categories** and read only those JSONs:

| Task Type | Categories to Load |
|-----------|-------------------|
| Code review / refactor | `development-tools`, `programming-languages`, `security` |
| New feature | `development-team`, `programming-languages`, `database`, `development-tools` |
| Architecture design | `expert-advisors`, `development-team`, `devops-infrastructure` |
| Security audit | `security`, `development-tools`, `devops-infrastructure` |
| Database work | `database`, `data-ai`, `performance-testing` |
| Frontend / UI | `web-tools`, `development-team`, `ui-analysis`, `performance-testing` |
| DevOps / Deploy | `devops-infrastructure`, `git`, `security` |
| Research / Analysis | `deep-research-team`, `data-ai`, `documentation` |
| API design | `api-graphql`, `development-team`, `documentation` |
| MCP development | `mcp-dev-team`, `development-tools` |
| Marketing / Business | `business-marketing`, `documentation` |
| Video / Audio | `ffmpeg-clip-team`, `media` |
| Blockchain / Web3 | `blockchain-web3`, `security`, `finance` |
| Game dev | `game-development`, `programming-languages` |
| Obsidian | `obsidian-ops-team` |
| OCR / Documents | `ocr-extraction-team`, `document-processing` |

Read each category JSON like:
```
Read ~/.claude/skills/nobrainer-team-builder/categories/programming-languages.json
```

Each file contains: `{ "agent-name": "description", ... }`

### Step 3: Select Agents (max 10)

From loaded categories, pick **best 3-10 agents**:
- **Task match**: Agent's description directly addresses the task
- **Tech match**: Agent knows the specific technologies
- **Complementary coverage**: Don't pick 3 code reviewers
- **Stop when sufficient**: Don't add agents that won't contribute

**Team sizes:**
- Simple (review, debug): 3-5 agents
- Medium (feature, refactor, audit): 5-8 agents
- Complex (architecture, migration): 8-10 agents

### Step 4: Present the Team

Before spawning, show:

```
NBTeam for: "{task summary}"
Categories loaded: programming-languages, development-tools, security

| # | Agent | Category | Role in This Task |
|---|-------|----------|-------------------|
| 1 | python-pro | programming-languages | Core implementation |
| 2 | test-engineer | development-tools | Test coverage |
| 3 | security-auditor | security | Security review |

Spawn all? (or adjust)
```

### Step 5: Spawn Agents

For each selected agent:
1. Read full `.md` from `~/.claude/skills/nobrainer-team-builder/agent-catalog/{category}/{name}.md`
2. Spawn via Agent tool:
   - `name`: `nbteam-{agent-name}`
   - `prompt`: Agent persona + task + project context
   - `description`: Short task summary
3. **Parallel** for independent agents, **sequential** for dependent ones

**Agent prompt template:**
```
You are {agent-name}. Here is your persona and expertise:

---
{full content of agent .md file}
---

Your task: {user's specific request}

Context about the project:
{relevant project context — CLAUDE.md, file structure, etc.}
```

### Step 6: Synthesize Results

- Collect all agent outputs
- Highlight agreements and conflicts
- Present unified recommendation
- If agents disagree, explain tradeoffs

## Categories Reference (27 categories, 401 agents)

| Category | Count | Focus |
|----------|-------|-------|
| ai-specialists | 6 | AI/ML strategy, ethics, prompts |
| api-graphql | 8 | API design, GraphQL, REST |
| blockchain-web3 | 4 | Smart contracts, Web3 |
| business-marketing | 18 | Product, sales, legal, analytics |
| data-ai | 38 | ML, data science, NLP, CV, quant |
| database | 11 | SQL, NoSQL, Supabase, Neon, optimization |
| deep-research-team | 16 | Research, analysis, fact-checking |
| development-team | 16 | Full-stack, frontend, backend, mobile |
| development-tools | 30 | Testing, debugging, code review, profiling |
| devops-infrastructure | 37 | CI/CD, cloud, Kubernetes, Terraform, monitoring |
| documentation | 11 | Technical writing, API docs, diagrams |
| expert-advisors | 52 | Architecture review, dependency management |
| ffmpeg-clip-team | 8 | Video/audio processing |
| finance | 5 | Fintech, trading, payments |
| game-development | 5 | Unity, Unreal, game design |
| git | 3 | Git workflow, branching strategies |
| mcp-dev-team | 8 | MCP server development |
| modernization | 3 | Legacy migration, cloud modernization |
| obsidian-ops-team | 7 | Obsidian vault management |
| ocr-extraction-team | 7 | OCR, document analysis |
| performance-testing | 5 | Load testing, web vitals |
| podcast-creator-team | 11 | Podcast production |
| programming-languages | 49 | Python, JS, Rust, Go, C#, PHP, etc. |
| realtime | 2 | WebSockets, Supabase Realtime |
| security | 20 | Pentesting, compliance, incident response |
| ui-analysis | 5 | Screenshot analysis, UI review |
| web-tools | 16 | React, Next.js, SEO, accessibility |

## Rules

- **Max 10 agents per task** — diminishing returns beyond that
- **Load only relevant category JSONs** — never read all 27 at once
- **Read agent .md only when spawning** — don't pre-read all 401 files
- **Parallel by default** — spawn independent agents in parallel
- **Present team first** — always show before spawning, accept adjustments
- **No permanent installation** — agents are temporary subagents, they don't persist
