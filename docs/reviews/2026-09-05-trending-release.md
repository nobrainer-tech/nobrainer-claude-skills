# Trending-wide release decisions — 2026-09-05

## Scope and evidence

The [full screen](2026-09-05-trending-screen.md) records all 435 distinct
discoveries from 36 repository/developer Trending views. Screening covered
metadata for every entry; selected primary sources received deeper review.
ECC received a twelve-file source audit. Other entries are not represented as
435 executed or security-audited projects. No external installer was run.

This release improves one concrete runtime boundary and the first-use path.
It does not claim that the suite is universally better than these projects,
that low-cost models equal larger models, or that a subprocess limit controls
the host's context, memory or account spend.

## Adopt, retain, defer

| Source | Decision | NB implementation or reason |
|---|---|---|
| [ECC context monitor](https://github.com/affaan-m/ECC/blob/e04ea0b9cc8248686edf5ac751cadff550e162b8/scripts/hooks/ecc-context-monitor.js#L274-L296) | Implement a distinct executable boundary | The inspected hook emits advisory context and intentionally does not block tools. NB adds an independent stdlib command runner for wall-time and captured-output limits; no ECC code is copied. |
| [ECC verification workflow](https://github.com/affaan-m/ECC/blob/e04ea0b9cc8248686edf5ac751cadff550e162b8/skills/verification-loop/SKILL.md) | Retain existing verification ownership | A command exit and task acceptance are different. NB already requires evidence appropriate to the result; a runner receipt does not approve the work. |
| [ECC installer](https://github.com/affaan-m/ECC/blob/e04ea0b9cc8248686edf5ac751cadff550e162b8/scripts/install-plan.js) | No duplicate installer | NB already previews destinations, supports explicit subsets and refuses foreign targets. |
| [gstack](https://github.com/garrytan/gstack/blob/0d1bd5616c0ef096bb7ccee336f63c60ee408618/README.md) | Improve first use | Move guarded installation before diagrams and add copyable trials with acceptance criteria. Do not adopt the author's productivity numbers. |
| [AWS AI-DLC](https://github.com/awslabs/aidlc-workflows/blob/a277af218f0df7f325d3b8be7b6d90fce2c5bd40/README.md) | Retain one canonical source | Generated multi-host surfaces reinforce our existing shared-tree boundary. No new stage framework or permanent roster is justified for this release. |
| [Agent Safehouse](https://github.com/eugene1g/agent-safehouse/blob/1fd7a1bb2cb74b68f5c8ff35b6822d0caf919b06/README.md) | Preserve scope distinction | OS sandboxing is different from timeout/process-group control. The new runner is not a filesystem/network security boundary. No sandbox is installed by this release. |
| [Bash Guard](https://github.com/dabit3/bash-guard/blob/b9b88a85719ec29401bcf817df203fa550471335/README.md) | Defer broad command hooks | Hook matching and trust vary by host. This release uses explicit argv invocation, not a silently installed global command filter. |
| [anti-slop](https://github.com/dmmulroy/anti-slop/blob/e8c4880471b23ab7f216fba7b27d173a6ef07d4c/README.md) | Keep project-specific quality rules optional | An opinionated JS/TS lint policy is not a universal cross-task default. Existing project checks remain authoritative. |
| [Fernando Skills](https://github.com/Klerith/fernando-skills/blob/1f9bcb4b9a478b0300bacfa8f43b021ab884f774/README.md) | Retain focused clarification | Its spec/implementation split reinforces explicit acceptance; no duplicate permanent spec skill is needed. |
| [Agent concurrency reference](https://github.com/chengyongru/awesome-agent-concurrency/blob/eb78ee06a8ff1da2096c068536c6a1e571c037db/README.md) | Retain receive-audit | Check source identity and current state before accepting a worker result; no new queue/controller is added. |
| [WorldFlowAI distribution](https://github.com/WorldFlowAI/everything-claude-code/blob/432485ba6b92c14fb357276a98957f348bcff9ee/README.md) | Attribute shared upstream | Its README refers to the ECC collection. Do not inflate competition counts by treating shared source claims as independent evidence. |
| [CAR](https://github.com/Git-on-my-level/codex-autorunner/blob/065f435d6120f95135425d8cc2df52760872a2d3/README.md) | Defer persistent ticket runtime | A durable cross-agent queue is a larger product/runtime decision; not required for an explicit command guard. |

The remaining specialist catalogs, runtimes and unrelated projects are listed
with evidence level in the full screen. Metadata-only discoveries remain leads,
not adopted capabilities or claims of relative quality.

## Product comparison boundary

ECC OSS, ecc.tools hosted GitHub App, AgentShield and operator services must be
compared separately. NoBrainer can include scripts, hooks and adapters, but
can claim only their tested scope. New website comparisons cover ECC, AWS
AI-DLC and gstack; existing source pages are reused for prior inspirations.

## Verification

The next release record owns final test results and publication evidence:
[v1.7.0](../releases/v1.7.0.md). This report does not promote a behavioral
benchmark or an unverified external service claim.
