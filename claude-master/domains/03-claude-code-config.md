# Domain 3: Claude Code Configuration & Workflows (20%)

Separates casual users from people who configured Claude Code for a team.

## CLAUDE.md Hierarchy

### Three Levels
- **User-level** (`~/.claude/CLAUDE.md`): applies only to YOU. NOT version-controlled. NOT shared via git.
- **Project-level** (`.claude/CLAUDE.md` or root `CLAUDE.md`): applies to everyone. Version-controlled. Shared.
- **Directory-level** (subdirectory `CLAUDE.md`): applies when working in that specific directory.

### Exam's Favourite Trap
New team member not receiving instructions -> root cause: instructions in user-level config instead of project-level.

### Modular Organisation
- `@import` syntax to reference external files from CLAUDE.md
- `.claude/rules/` directory for topic-specific rule files (alternative to one massive file)
- `/memory` command to verify which memory files are loaded (debugging inconsistent behaviour)

## Custom Slash Commands and Skills

### Directory Structure
- `.claude/commands/` = project-scoped, shared via version control
- `~/.claude/commands/` = personal, not shared
- `.claude/skills/` with SKILL.md = on-demand invocation with configuration

### Skill Frontmatter Options
- `context: fork` -- runs in isolated sub-agent context, verbose output stays contained
- `allowed-tools` -- restricts which tools the skill can use
- `argument-hint` -- prompts for required parameters when invoked without arguments

### Personal Skill Customization
Create personal variants in `~/.claude/skills/` with different names to avoid affecting teammates. Example: team has `/review` skill, you create personal `~/.claude/skills/my-review/SKILL.md` with custom verbosity.

### Key Distinction
- Skills = on-demand, task-specific workflows (loaded when invoked)
- CLAUDE.md = always-loaded, universal standards (loaded every time)

## Path-Specific Rules

### .claude/rules/ Files
YAML frontmatter with glob patterns:
```yaml
---
paths: ["terraform/**/*"]
---
Rules only apply when editing matching files.
```

### Key Advantage Over Directory-Level CLAUDE.md
Glob patterns match files across ENTIRE codebase. `**/*.test.tsx` catches every test file regardless of directory. Directory-level CLAUDE.md only applies within that one directory.

### Token Efficiency
Path-scoped rules load ONLY when editing matching files. Not always.

## Plan Mode vs Direct Execution

### Plan Mode When
- Complex tasks involving large-scale changes
- Multiple valid approaches exist
- Architectural decisions required
- Multi-file modifications (e.g., library migration affecting 45+ files)

### Direct Execution When
- Well-understood changes with clear, limited scope
- Single-file bug fix with clear stack trace
- Adding a date validation conditional

### Explore Subagent
Isolates verbose discovery output from main conversation. Returns summaries to preserve main context.

## Iterative Refinement

### Technique Hierarchy (most effective first)
1. **Concrete input/output examples** (2-3 before/after): beats prose descriptions every time
2. **Test-driven iteration**: write tests first, share failures to guide improvement
3. **Interview pattern**: have Claude ask questions before implementing

### Batch vs Sequential Feedback
- Single message when fixes interact with each other
- Sequential iteration when issues are independent

## CI/CD Integration

### -p Flag
Runs Claude Code in non-interactive mode (print mode). Without it, CI job hangs waiting for input.

### Structured CI Output
`--output-format json` with `--json-schema` produces machine-parseable structured findings.

### Session Context Isolation
Same Claude session that generated code is LESS effective at reviewing its own changes. Use independent review instance.

### Incremental Review Context
Include prior review findings when re-running. Instruct to report ONLY new or unaddressed issues.

## Agent Skills (from Course 14)

### What Skills Are
Markdown files that teach Claude how to handle specific tasks. Each skill bundles instructions and can include tools, configuration, and sub-skill references.

### Skill Structure
```
skill-name/
  SKILL.md        # Main skill file (always loaded)
  subdirectory/   # Supporting files (loaded on demand)
```

### Skills Work Across Surfaces
Skills work in chat, Claude Code, anywhere Claude runs. A plugin is the Cowork-specific bundling of skills with connectors.

## Subagent Configuration (from Course 15)

### Creating Custom Subagents
Config at `.claude/agents/name.md`:
```yaml
---
name: code-quality-reviewer
description: Review code for quality, security, best practices
tools: Bash, Glob, Grep, Read, WebFetch, WebSearch
model: sonnet
color: purple
---
```

### Tool Categories for Subagents
- Read-only tools (safe, no side effects)
- Edit tools (modifies files)
- Execution tools (runs code)
- MCP tools (external integrations)

### Model Selection
- Haiku: fast, lightweight tasks
- Sonnet: balanced speed/depth
- Opus: complex analysis
- Inherit: uses parent's model

## Quiz-Validated Facts
- Chat app too slow -> Use streaming
- Consistent format extraction -> Temperature close to 0
- Customer service bot -> System prompt
- Follow-up questions -> Send whole conversation history
- API key storage -> On your secure server
- System prompt purpose -> Customize Claude's tone, style, approach
- Clean JSON output -> Prefill with "{" and stop sequence
- Control response direction -> Assistant message prefilling
