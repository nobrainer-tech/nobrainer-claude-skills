# Bounded orchestration review — 2026-09-05

Baseline and retained champion: released v1.6.0, commit `d51d1e1`. The first
instruction candidate was rejected after comparison and fully rolled back.
This report records research, an optional operating design and a negative
experiment result. It is not a new release, installed-client update, resource
limiter or evidence of lower billing. Private incident material and the supplied
design document remain outside this public repository.

## Findings and response

Existing instructions already keep one primary agent, optional workers, scoped
handoffs and a session-health gate. The remaining gap is operational: health
limits can be unset, and the lightweight native-worker path does not require a
finite input/output or aggregate task allowance. Model routing also leaves
supervisor versus worker effort implicit. A low-priced model name cannot bound
a long conversation or guarantee a lower total cost.

The rejected candidate kept the fifteen-skill portfolio and added one shared
execution-budget reference. Explicit economical delegation selected `ROUTED`: a capable
supervisor owns scope, remaining allowance and acceptance; a cheaper capable
worker receives a fresh scoped packet. Host-selected single-agent work remains
the default. Normal effort is the starting point, with escalation tied to an
observed reasoning gap and supported settings.

It proposed finite unit, report and retry defaults for native and durable
workers, with an aggregate allowance preserved through retries, compaction and
model changes. This larger packet definition made source identity less reliable
in the tested model. These proposed defaults were not installed as active policy.
Saved transcript size, model input, billing and process memory remain separate
measurements; prompt instructions alone cannot implement a host watchdog.

## Research decisions

The original [September 3 X collection](https://x.com/chenchengpro/status/2095461259949052264)
was posted at 10:37:50 UTC and harvested at 14:22:10 UTC that day. Discovery is
recent; popularity and the author's claims are not acceptance evidence.

| Candidate | Decision for this suite |
|---|---|
| [dev-pair](https://github.com/justinjohnson25600/hermes_skills/tree/main/dev-pair) | Borrow bounded review and structured evidence principles. Existing Review owns acceptance; no mandatory second provider or Hermes dependency. No upstream code imported. |
| [reverse-skill](https://github.com/zhaoxuya520/reverse-skill) | Do not import the broad security package or bootstrap. Use existing Research for contract tracing and Security for authorized security work; evaluate a temporary specialist only for a specific missing capability. |
| [Graphify](https://github.com/Graphify-Labs/graphify) | Pilot only when a large-repository retrieval bottleneck is measured. The source screenshot identifies `safishamsi/graphify`; that exact URL now redirects to this repository. No compulsory index or social-post savings number. |
| [Open Aware](https://github.com/qodo-ai/open-aware) | Defer a service dependency. Its maintained description limits the free remote MCP to pre-indexed public repositories; it is not a general local/private-repository solution. |

The Open Aware bookmark was published September 10, 2025 and harvested July 26,
2026; it is not a newly published tool. The [Graphify bookmark](https://x.com/adrianaia_/status/2041818475417792778)
is dated April 9, 2026 in the normalized note; its ingestion timestamp was not
verified. Source dates and ingestion dates must stay separate. Any index needs
source-revision checks and decisive source-file readback before acceptance.

Anthropic's [context-engineering guidance](https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents)
supports selective retrieval and isolated work with concise returns. OpenAI's
[subagent documentation](https://developers.openai.com/codex/subagents/)
describes host-specific subagent configuration. Neither source proves that all
clients expose fresh context, model selection or enforceable budgets. The
portable policy records those limits and supports sequential execution.

## The supplied multi-session courier design

The owner-supplied document was retrieved and read in full on September 5. It
defines a neutral courier, a coordinator, thematic tracks and an optional remote
worker. The courier forwards the exact payload and appends a delivery record;
it does not summarize, review, accept work or update project status. The
coordinator owns sequencing, integration and the canonical plan. Workers retain
judgment inside their scope, verify evidence and return a complete Markdown
report. Remote environments must not be assumed to share files.

The useful responsibilities already map to the current portfolio:

| Supplied role | Existing owner and recommended use |
|---|---|
| Coordinator | Ultra owns outcome and acceptance; Dispatcher activates only for a real dependent queue. |
| Courier | Sessions owns identity, transport, delivery/ACK and receive-audit. A deterministic transport function needs no LLM or standing conversation. |
| Thematic track | Team selects an actual work unit and owning specialist; start a bounded native worker only when useful. |
| External worker | Sessions verifies host, artifact transfer, source identity and write ownership; a local path alone does not prove delivery to another host. |

Use one MAIN by default and normally zero or one active worker. Two independent
units can justify two workers. The document's six standing sessions are an
optional arrangement for a demonstrated workload, not a package default. Roles
do not need a one-to-one mapping to always-running models.

A practical configuration for the owner's advertised host is Sol low/medium as
supervisor, with a suitable lower-cost model for well-defined execution. Luna
maximum effort is an option to test for a hard unit, not an automatic economy
choice. `low` is an advertised setting; `light` was not advertised. The portable
suite must resolve these roles from each client's actual inventory. It cannot
change the current MAIN model merely by spawning planning help.

Keep one canonical task state and a small append-only transport log. A worker
authors the compact report and retains full evidence at an accessible artifact
reference. The courier forwards it unchanged and verifies payload identity;
the coordinator opens decisive source/diff/test evidence before acceptance.
Do not copy a full report into several persistent chats or let a courier rewrite
it to save tokens. Reuse the exact identity, context hash, payload hash,
idempotency, delivery and ACK fields from the existing
[Sessions protocol](../../skills/nobrainer-sessions/references/protocol.md).
Unavailable native transport can use an explicit manual artifact transfer;
delivery and content acceptance remain different states.

No mailbox service, gateway, transport adapter or standing session team was
installed. This is an assessed operating design; end-to-end multi-host delivery
and cost savings remain unverified.

## Evidence status

Three paired development repetitions and one sealed holdout batch per variant
completed: eight successful CLI calls, no model retries. Requested model:
`gpt-5.6-sol`, effort `low`, Codex CLI `0.149.1`; backend identity was not exposed.
No model tool calls occurred. These were policy simulations, not real delegated
implementation or evidence of native skill discovery.

| Result | Baseline | Rejected candidate |
|---|---|---|
| Development totals, out of 30 | 30, 30, 28 | 28, 28, 28 |
| Mean | 29.33 | 28.00 |
| Held-out total, out of 20 | 20 | 20 |
| Hard safety gates | Pass | Pass |

The candidate omitted the required input/context hash in both delegation cases
in all three repetitions; the baseline did so in one repetition. Paired deltas
were -2, -2, 0. The promotion threshold failed, so the active source stayed at
the baseline. The rubric also had a ceiling limitation: a +1 mean gain was
unreachable from 29.33/30. This limits conclusions about potential improvement;
it does not erase the observed repeated regression. Do not tune this candidate
against the revealed holdout.

Input usage was 27,066–28,601 tokens per call. The CLI emitted a skills-context
warning despite an isolated directory, ephemeral calls, ignored user config and
disabled tool features. `--ignore-rules` disables execpolicy rules, not skill or
project instructions. The input includes supplied evaluation policy as well as
host context; this observation does not attribute all those tokens to the global
skill catalog. `--ephemeral` avoids new persisted session files; it does not prove
a small prompt, low RAM or low billing. Model routing alone cannot fix all client
overhead.

Raw cases, rubric, outputs, hashes and the rejected diff are retained in the
operator's private evidence archive. Receipt-manifest SHA-256:
`375aa68b2e2967ab86c73477ea36d3a0da48d1e5b69c8592c475508bf1b1c906`.
No public performance or compatibility claim follows from this private smoke.
Final readback confirmed zero diff from `d51d1e1` in operational skills, adapters,
README, diagrams, compatibility/testing docs, tests and AGENTS/CLAUDE. Both skill
validators passed, all 125 unit tests passed, and `git diff --check` passed.
Independent review accepted the research/proposal/proof distinctions after this
closeout was updated. Only this report, the task tracker and scoped lesson remain
as local changes. No commit, publication, global installation or model-setting
change occurred. The attached browser and Telegram client were disconnected.
