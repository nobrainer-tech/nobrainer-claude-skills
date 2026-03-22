# Domain 2: Tool Design & MCP Integration (18%)

Tool descriptions are the primary mechanism Claude uses for tool selection. Vague/overlapping descriptions cause misrouting.

## Tool Interface Design

### What Good Tool Descriptions Include
- What the tool does (primary purpose)
- What inputs it expects (formats, types, constraints)
- Example queries it handles well
- Edge cases and limitations
- Explicit boundaries: when to use THIS tool vs similar tools

### Misrouting Problem
Two tools with overlapping descriptions -> selection confusion.
Fix: **expand descriptions** with clear boundaries.
NOT few-shot examples (token overhead, wrong root cause).
NOT routing classifiers (over-engineered).
NOT tool consolidation (too much effort).

### Tool Splitting
Split generic tools into purpose-specific ones:
`analyze_document` -> `extract_data_points`, `summarize_content`, `verify_claim_against_source`

### System Prompt Interaction
Keyword-sensitive instructions in system prompts can create unintended tool associations that override descriptions.

## Structured Error Responses

### MCP isError Flag Pattern
Use `isError` flag for communicating failures.

### Four Error Categories
1. **Transient**: timeouts, service unavailability -> retryable
2. **Validation**: invalid input -> fix input, retry
3. **Business**: policy violations -> NOT retryable, needs alternative workflow
4. **Permission**: access denied -> needs escalation or different credentials

### Critical Distinction
- **Access failure**: tool could not reach data source -> consider retry
- **Valid empty result**: tool reached source, found nothing -> this IS the answer, do NOT retry

### Error Response Metadata (exam-tested)
Return structured metadata: `errorCategory` (transient/validation/business/permission), `isRetryable` boolean, human-readable description. For business violations include `retriable: false` with customer-friendly explanation. Generic "Operation failed" prevents intelligent recovery.

### Multi-Agent Error Propagation
- Subagents implement local recovery for transient failures
- Only propagate errors they cannot resolve locally
- Include partial results with error context

## Tool Distribution and tool_choice

### Tool Overload Problem
18 tools degrades selection reliability. Optimal: **4-5 tools per agent**.

### tool_choice Configuration
- `"auto"`: model decides tool or text (default)
- `"any"`: MUST call a tool, picks which (guaranteed structured output)
- `{"type":"tool","name":"extract_metadata"}`: MUST call specific tool (forced first step)

### Scoped Cross-Role Tools
For high-frequency simple operations, give constrained tool directly to the agent that needs it. Avoids coordinator round-trip latency for 85% of simple cases.

## MCP Server Configuration

### Scoping Hierarchy
- **Project-level**: `.mcp.json` in repo. Version-controlled. Shared.
- **User-level**: `~/.claude.json`. Personal. NOT shared.

### Environment Variable Expansion
`.mcp.json` supports `${GITHUB_TOKEN}` syntax. Keeps credentials out of version control.

### MCP Resources
Expose content catalogs as MCP resources. Gives agents visibility into available data without exploratory tool calls.

### Build vs Use
- Use community MCP servers for standard integrations (Jira, GitHub, Slack)
- Build custom only for team-specific workflows

## MCP Architecture (from Courses 06, 09)

### Three Primitives
- **Tools**: functions Claude can call (server exposes, Claude invokes)
- **Resources**: data sources for context (@document_name references)
- **Prompts**: pre-tested workflows triggered by users (not Claude)

### Key Distinction
- Tools = Claude-initiated (AI decides when to call)
- Resources = App-initiated (user/app fetches for context)
- Prompts = User-initiated (user directly triggers)

### Three Components
- **Host**: application (Claude Desktop, IDE)
- **Client**: manages connection to server
- **Server**: exposes tools/resources/prompts

### Transports (from Course 09)
- **STDIO**: same machine, simplest, stdin/stdout
- **StreamableHTTP**: remote servers over HTTP, uses SSE for bidirectional
- `stateless_http=True`: horizontal scaling but loses sessions/sampling/progress
- `json_response=True`: disables streaming, plain JSON only

### Connection Sequence
Initialize Request -> Initialize Result -> Initialized Notification (3-message handshake)

### Sampling (from Course 09)
Server accesses LLM through connected client. Reduces server complexity, no API keys on server.

### Roots (from Course 09)
Grant servers access to specific files/folders. MCP SDK does NOT auto-enforce -- you must implement `is_path_allowed()` yourself.

## Built-in Tools

### Grep vs Glob
- **Grep**: searches file CONTENTS for patterns (function callers, error messages, imports)
- **Glob**: matches file PATHS by naming patterns (files by extension, config files)

### Read/Write/Edit
- **Edit**: targeted modifications using unique text matching (fast, precise)
- **Read + Write**: fallback when Edit cannot find unique anchor text

### Incremental Codebase Understanding
Start with Grep to find entry points, use Read to follow imports. Do NOT read all files upfront.

## Quiz-Validated Facts
- Test MCP server -> Use MCP Inspector
- Document reference @name -> Resources
- Communication on same machine -> Standard input/output (STDIO)
- MCP benefit -> Handles tool definitions and execution for you
- Define tool easiest -> @mcp.tool decorator
- Pre-tested workflow -> Prompts
- Force specific tool -> {"toolChoice": {"tool": {"name": "tool-name"}}}
- JSON schema most important -> Detailed descriptions of tool and parameters
- Without MCP -> Write and maintain all tool functions yourself
- MCP three components -> Host, Client, Server
- What is MCP -> Standardized protocol for secure connections to external data
