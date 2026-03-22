# Claude Master - Certified Architect Knowledge Base

Expert knowledge base for Claude platform mastery. Covers all 5 exam domains with actionable patterns, anti-patterns, and decision frameworks from Anthropic Academy courses + Claude Certified Architect study guide.

## Trigger

Activate when user asks about:
- Claude architecture, agentic patterns, multi-agent orchestration
- MCP servers, tool design, tool_choice configuration
- Claude Code configuration, CLAUDE.md, skills, hooks, CI/CD
- Prompt engineering, structured output, few-shot, batch API
- Context management, escalation, error propagation, provenance
- Keywords: "claude master", "architect exam", "claude best practice"

## Domains (weighted by exam importance)

| # | Domain | Weight | File |
|---|--------|--------|------|
| 1 | Agentic Architecture & Orchestration | 27% | `domains/01-agentic-architecture.md` |
| 2 | Tool Design & MCP Integration | 18% | `domains/02-tool-design-mcp.md` |
| 3 | Claude Code Configuration & Workflows | 20% | `domains/03-claude-code-config.md` |
| 4 | Prompt Engineering & Structured Output | 20% | `domains/04-prompt-engineering.md` |
| 5 | Context Management & Reliability | 15% | `domains/05-context-management.md` |
| 6 | Cloud Platforms (Bedrock & Vertex) | -- | `domains/06-cloud-platforms.md` |

## How to use sub-domain files

Load the relevant domain file based on the user's question. If the question spans multiple domains, load all relevant files.

| Question about | Load |
|----------------|------|
| Agentic loops, stop_reason, subagents, orchestration, hooks, decomposition, sessions | Domain 1 |
| Tool descriptions, tool_choice, MCP config, error responses, Grep/Glob, built-in tools | Domain 2 |
| CLAUDE.md, skills, commands, rules/, plan mode, CI/CD, -p flag, iterative refinement | Domain 3 |
| Prompts, few-shot, structured output, tool_use JSON, batch API, validation-retry | Domain 4 |
| Context preservation, escalation, error propagation, provenance, confidence calibration | Domain 5 |
| Bedrock, Vertex AI, AWS SDK, Google Cloud, model selection, API differences | Domain 6 |

## Quick Decision Frameworks

### When to use hooks vs prompts
- Financial/security/compliance risk -> Programmatic hooks (100% enforcement)
- Style/formatting/low-stakes -> Prompt-based guidance (probabilistic)

### When to use plan mode vs direct execution
- Multi-file, architectural, migration -> Plan mode
- Single-file bug fix, clear scope -> Direct execution

### When to use subagents vs inline
- Verbose discovery, parallel tasks, context isolation -> Subagents
- Quick lookup, single file edit -> Inline

### When to use batch API vs synchronous
- Overnight reports, weekly audits, cost savings -> Batch API (50% cheaper)
- Pre-merge checks, blocking workflows -> Synchronous API

### Tool selection: tool_choice options
- `"auto"` -> Model decides (default, may return text only)
- `"any"` -> Must call a tool, picks which (guaranteed structured output)
- `{"type":"tool","name":"X"}` -> Must call specific tool (forced first step)

## Key Anti-Patterns to Reject

1. Parsing natural language to determine loop termination
2. Arbitrary iteration caps as primary stopping mechanism
3. Assuming subagents share coordinator memory
4. Vague tool descriptions causing misrouting
5. User-level CLAUDE.md for team-shared instructions
6. "Be conservative" instead of explicit categorical criteria
7. Progressive summarisation of transactional data
8. Sentiment-based escalation triggers
9. Silent error suppression returning empty results as success
10. Self-review in same session (use independent instance)

## 6 Exam Scenarios (4 picked randomly per exam)

| # | Scenario | Primary Domains | Key Tools |
|---|----------|----------------|-----------|
| 1 | Customer Support Resolution Agent | 1, 2, 5 | get_customer, lookup_order, process_refund, escalate_to_human |
| 2 | Code Generation with Claude Code | 3, 5 | CLAUDE.md, slash commands, plan mode |
| 3 | Multi-Agent Research System | 1, 2, 5 | Task tool, coordinator, subagents |
| 4 | Developer Productivity Tools | 2, 3, 1 | Read, Write, Bash, Grep, Glob + MCP |
| 5 | Claude Code for CI/CD | 3, 4 | -p flag, --output-format json, review prompts |
| 6 | Structured Data Extraction | 4, 5 | tool_use, JSON schemas, batch API |

## Sample Questions with Correct Answers

- Skip get_customer -> misidentified refunds -> **Programmatic prerequisite gate** (not prompt/few-shot)
- Tool misrouting, vague descriptions -> **Expand tool descriptions** (not routing classifier/consolidation)
- Escalates simple cases, handles complex -> **Explicit criteria + few-shot examples** (not sentiment/confidence)
- Team slash command /review -> **`.claude/commands/` in project repo** (not ~/.claude or CLAUDE.md)
- Monolith restructuring -> **Plan mode** (not direct execution)
- Test file conventions across dirs -> **`.claude/rules/` with glob patterns** (not directory-level CLAUDE.md)
- Narrow topic decomposition -> **Coordinator decomposition too narrow** (not downstream agents)
- Subagent timeout -> **Structured error context** (not generic status/suppression/termination)
- Synthesis fact-checking latency -> **Scoped verify_fact tool** (not batch/full access/caching)
- CI pipeline hangs -> **-p flag** (not CLAUDE_HEADLESS/--batch/stdin redirect)
- Batch vs real-time -> **Batch for overnight only** (not both batch/both real-time)
- 14-file inconsistent review -> **Per-file + cross-file passes** (not split PRs/bigger model/consensus)

## Course Sources

Based on 15 Anthropic Academy courses (all completed 100%) + Official Anthropic Exam Guide (v0.1):
- 01: Claude Code in Action | 05: Building with Claude API
- 06: Intro to MCP | 09: MCP Advanced Topics
- 10: Claude with Bedrock | 11: Claude with Vertex AI
- 14: Agent Skills | 15: Subagents
- Plus: AI Fluency courses (04, 07, 08, 12, 13), Claude 101 (02), Cowork (03)
