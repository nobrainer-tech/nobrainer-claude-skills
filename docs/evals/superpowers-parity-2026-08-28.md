# Superpowers parity audit — 2026-08-28

Status: `LOCAL CONTRACT GATES PASSED / CLIENT RUNTIME NOT VERIFIED`

This audit asks whether NoBrainer Tech Skills has the product discipline of a
mature multi-harness skill repository without copying Superpowers' portfolio or
always-on behavior. It covers repository structure, adapters, deterministic
tests, documentation, visual entry point and evidence boundaries. It does not
claim marketplace publication, clean-client runtime or buyer usefulness.

## Reference snapshot

The comparison used official
[`obra/superpowers`](https://github.com/obra/superpowers) release `v6.3.0` at
commit `b36e0829c6d0140e93cfef2ca599b1b07d4a7797`.

Observed reusable product patterns:

- one canonical skill tree rather than client-specific forks;
- thin per-harness manifests, hooks or in-process adapters;
- deterministic adapter tests in addition to Markdown validation;
- a small startup/bootstrap layer with explicit deduplication;
- separate source, repository-contract, client-load, runtime and distribution
  proof;
- release-facing documentation, contribution gates and rollback.

The audit did not adopt Superpowers' fourteen-skill inventory, mandatory
“consider a skill before every action” policy, implementation methodology, or
large bootstrap. Those would duplicate the external dependency and conflict
with NoBrainer's “small task stays small” contract.

## Baseline gap

The nine curated NoBrainer skills and five initial client surfaces were already
validated, but cross-harness support was uneven:

- only OpenCode had executable adapter behavior;
- Claude and Cursor startup routing had no shared tested hook;
- Gemini, Kimi and Pi had no dedicated package surface, while Devin and Hermes
  had no proved client-specific contract;
- public compatibility language did not separate local contract checks, client
  loading and runtime behavior across those harnesses;
- the previous hero visual omitted several active skills.

The frozen RED tests required one portable bootstrap, exact proved platform
JSON, OpenCode deduplication, Pi compaction behavior, conservative manifests and
one replacement hero. They failed on the baseline because those files and
behaviors did not exist.

## Candidate design

- Keep exactly nine discoverable `SKILL.md` files. No bootstrap or adapter is a
  tenth skill.
- Use one 111-word `adapters/bootstrap.md` that routes non-trivial work to
  `nobrainer-ultra`, keeps obvious one-step work direct, preserves owner gates
  and fails closed when visible session transport is unavailable.
- Bind Claude and Cursor hooks to that file with one JSON shape per platform.
- Register the canonical tree and inject the marker once in OpenCode and Pi;
  allow Pi to re-inject once after compaction.
- Use extension/plugin manifests for Gemini and Kimi.
- Keep the root Agent Plugins v1 manifest as the portable Hermes surface, with
  namespaced explicit skills and no automatic bootstrap claim. Omit a Devin
  manifest until its current discovery and startup contract is proved.
- Keep Codex hooks empty so Claude hook shapes are not auto-discovered.
- Replace the old partial hero with a 1672×941 map showing Decide, SDD,
  Sessions, Browser, RCA, Review, Wiki and Autoimprove feeding Ultra, then a
  verified outcome. Owner gates, evidence, rollback and the complete lifecycle
  remain visible.

## Acceptance evidence

Deterministic candidate checks cover:

- canonical inventory and portable frontmatter;
- bootstrap size, scope and public-clean boundary;
- two SessionStart JSON contracts;
- OpenCode path registration and one-time injection;
- Pi resource discovery, deduplication and post-compaction re-injection;
- portable Agent Plugin, Gemini and Kimi manifest contracts, plus rejection of
  invented Devin/Hermes adapters;
- PNG dimensions, size and README binding;
- installer conflicts, migration races, rollback and security policy;
- Python, Node and shell syntax on Linux and macOS CI;
- a checksum-pinned Gitleaks current-tree scan.

The local candidate passed both skill validators, all 56 unit tests, Python and
shell syntax, ShellCheck, Actionlint, JSON parsing, Claude/plugin validators and
current-tree plus staged Gitleaks scans. A bounded independent staged review
reported one P2: local adapter tests were labeled too much like client
acceptance. The candidate now separates `REPOSITORY_CHECKED`, `CLIENT_LOADED`
and `RUNTIME_VERIFIED`, with a regression test for that boundary.

Pull-request CI and merged-main readback are exact-commit release evidence and
must be checked on GitHub; this local report does not pre-claim them.

## Deliberate limits

- Adapter execution is not a clean-client transcript.
- No marketplace, package registry or GitHub release publication is implied.
- Unknown Agent Skills clients receive the portable source but no automatic
  bootstrap claim.
- Official Superpowers remains external and separately installed.
- Runtime-specific tool mappings stay in adapters, never in canonical skills.
- A hidden subagent is not represented as a visible NoBrainer session.

Rollback is a Git revert of this adapter/visual candidate. Skills-only local
installs are unaffected because the canonical nine skill directories and their
names do not change.
