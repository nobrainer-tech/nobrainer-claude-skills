# Domain 1: Agentic Architecture & Orchestration (27%)

Highest-weighted domain. Covers agentic loops, multi-agent orchestration, subagents, workflow enforcement, hooks, decomposition, and session management.

## Agentic Loop Lifecycle

The complete loop:
1. Send request to Claude via Messages API
2. Inspect `stop_reason` in the response
3. If `stop_reason` is `"tool_use"`: execute tools, append results to conversation, send back
4. If `stop_reason` is `"end_turn"`: agent finished, present final response

### Three Anti-Patterns (reject on sight)
- **Parsing natural language** to determine loop termination ("I'm done") -- natural language is ambiguous
- **Arbitrary iteration caps** as primary stopping mechanism ("stop after 10 loops") -- cuts useful work or runs unnecessary iterations
- **Checking for assistant text** as completion indicator -- model can return text alongside tool_use blocks

### Model-Driven vs Pre-Configured
- Model-driven: Claude reasons about which tool to call based on context (flexible)
- Pre-configured decision trees: fixed routing (predictable)
- Exam favours model-driven for flexibility, programmatic enforcement for critical business logic

## Multi-Agent Orchestration

### Hub-and-Spoke Architecture
- Coordinator agent at the centre
- Subagents are spokes for specialised tasks
- ALL communication flows through coordinator -- subagents never communicate directly
- Coordinator handles: task decomposition, invocation, context passing, result aggregation, error handling

### Critical Isolation Principle
- Subagents do NOT inherit coordinator's conversation history
- Subagents do NOT share memory between invocations
- Every piece of information must be explicitly included in the prompt
- This is the single biggest misconception tested

### Narrow Decomposition Failure
Coordinator decomposes "impact of AI on creative industries" only into visual arts -- missing music, writing, film. Test whether you can trace failures back to decomposition quality.

## Subagent Invocation and Context Passing

### Task Tool
- Mechanism for spawning subagents from coordinator
- Coordinator's `allowedTools` must include `"Task"`
- Each subagent has AgentDefinition with description, system prompt, tool restrictions

### Context Passing Best Practices
- Include complete findings from prior agents in subagent prompt
- Use structured data separating content from metadata (URLs, doc names, page numbers)
- Design coordinator prompts specifying research goals and quality criteria, NOT step-by-step procedures
- Emit multiple Task calls in single response for parallel spawning

### fork_session
Creates independent branches from shared analysis baseline for exploring divergent approaches.

## Workflow Enforcement and Handoff

### Enforcement Spectrum
- **Prompt-based guidance**: system prompt instructions. Works most of the time. Non-zero failure rate.
- **Programmatic enforcement**: hooks/prerequisite gates that physically block downstream tools. Works every time.

### Decision Rule
- Financial, security, compliance -> programmatic enforcement (hooks)
- Low-stakes formatting/style -> prompt-based guidance
- Exam presents prompt-based solutions for high-stakes scenarios -- reject them

### Structured Handoff
When escalating to human: compile customer ID, conversation summary, root cause, refund amount, recommended action. Human does NOT have access to conversation transcript.

## Agent SDK Hooks

### PostToolUse Hooks
- Intercept tool results after execution, before model processes them
- Use case: normalise data formats (Unix timestamps to ISO 8601)

### Tool Call Interception Hooks
- Intercept outgoing tool calls before execution
- Use case: block refunds above \$500, enforce compliance rules

### Decision Framework
- Hooks = deterministic guarantees (100% enforcement)
- Prompts = probabilistic guidance
- If business would lose money or face legal risk from a single failure -> use hooks

## Task Decomposition Strategies

### Fixed Sequential (Prompt Chaining)
- Predetermined steps, predictable, consistent, reliable
- Limitation: cannot adapt to unexpected findings
- Best for: structured, repeatable tasks

### Dynamic Adaptive
- Generate subtasks based on discoveries at each step
- Adapts to the problem, less predictable
- Best for: open-ended investigation

### Attention Dilution Problem
Processing too many files in single pass -> inconsistent depth.
Fix: per-file local analysis + separate cross-file integration pass.

## Session State and Resumption

### Options
- `--resume <session-name>`: continue named session (context still valid)
- `fork_session`: independent branch from shared baseline (divergent approaches)
- Fresh start with summary injection (files changed, context degraded)

### Stale Context
When resuming after code modifications, inform agent about SPECIFIC file changes for targeted re-analysis.

## Subagents (from Course 15)

### Why Subagents
- Separate context window for each subagent
- Intermediate steps (file reads, searches) stay isolated
- Only summary returns to main conversation
- Main context stays clean for longer sessions

### Built-in Subagents
- General purpose: multi-step tasks requiring exploration + action
- Explore: fast codebase searching and navigation
- Plan: research and analysis before presenting implementation plan

### Custom Subagents
Config file at `.claude/agents/name.md` with YAML frontmatter:
- `name`, `description`, `tools`, `model`, `color`
- Tool categories: Read-only, Edit, Execution, MCP, Other
- Model options: Haiku (fast), Sonnet (balanced), Opus (complex), Inherit

### Workflow Patterns (from Courses 05/10/11)
- **Parallelization**: send separate requests simultaneously for independent items
- **Chaining**: sequential focused steps (fixes rule-ignoring)
- **Routing**: route different content types to specialized pipelines
- **Evaluator-Optimizer**: write/check/improve cycle
- **Agent vs Workflow**: workflow for reliability/predictability, agent for flexibility
- Environment inspection: observe and understand results of actions

## Quiz-Validated Facts
- After Claude asks for external data -> your server runs code to fetch it
- Most flexibility -> abstract tools like read_file, write_file, run_command
- Reliability important -> use workflow (more reliable and testable)
- Known exact steps -> workflow with predetermined steps
- Environment inspection -> observe and understand results of actions
