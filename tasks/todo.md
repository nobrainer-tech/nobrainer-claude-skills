# Version 1.6.0 delivery

## Goal and acceptance

Deliver a small, portable skill suite that takes a clear outcome into authorized
execution, asks only material questions up front, shows concise progress, and
stops at verified completion or a concrete blocker. Publish version 1.6.0 with
accurate installation, model/client evidence and matching public documentation.

- AC01: Simple coding and non-coding work stays direct, without mandatory
  planning artifacts, a wiki, a team or unavailable client features.
- AC02: Ambiguous work gets one focused clarification round. Clear authorized
  work continues without routine confirmation, including after a checkpoint.
- AC03: Longer work uses one durable goal/TODO, bounded corrective attempts,
  evidence-based completion and a capability-based fallback to ordinary files.
- AC04: Specialists and subagents are optional, bounded and accountable;
  missing telemetry or native goal/session tools does not block safe local work.
- AC05: Project setup reuses existing instructions, specs and knowledge stores;
  SDD/TDD are chosen for an observed need rather than scaffolding by default.
- AC06: The fifteen-skill source, adapters, public instructions and release
  materials agree. Astra claims identify the exact tested host/model and limits.
- AC07: Deterministic checks, bounded behavior scenarios and independent review
  pass on final bytes; the published release and relevant web routes are read back.

## Scope and method

Expected files: Ultra and relevant orchestration references; affected bootstrap,
setup and project templates; existing behavioral/contract checks; README,
compatibility/testing/release documentation, version manifests and workflow diagram.
Expand this list only for a verified finding. Website changes belong in its own
source repository and only the `/skills/` integration surface.

Non-goals: new permanent skills, model gateway, autonomous infinite loops,
automatic global installations, framework/vendor code, social posts, paid products,
promises of popularity or universal runtime compatibility.

Protected: other checkouts, unrelated website changes, credentials and private
wiki content. MAIN is the only integration writer. Review and research workers
are read-only until explicitly assigned disjoint implementation scopes.

Model policy: STANDARD, host-selected model/effort; exact runtime smoke IDs are
recorded when used. No automatic escalation. Start with one independent research
scout, one source reviewer and one website scout (maximum three workers).
At most two corrective attempts per observed failure before a new diagnosis;
no repeat polling or evaluator tuning against failed holdouts.

Test decision: EXISTING checks plus behavioral regressions for reproduced gaps.
Static text assertions do not establish model behavior or client compatibility.
Public surface: UPDATE README, relevant docs, version files, diagram and website.
Authority: the owner requested review, fixes and publication of version 1.6 today;
this covers the focused branch/PR, merge, tag/release and matching skills page.
No authority for social posting or unrelated production changes.
Rollback: revert the focused release changes; previous release remains available.

## Progress

- [x] Resolve canonical checkout, current main, instructions and existing release.
- [x] Audit source, ecosystem/X research and public website.
- [x] Freeze minimal fixes against reproducible gaps; implement and document.
- [x] Run deterministic and behavior checks; review final changes independently.
- [ ] Publish 1.6.0 and verify release, source and relevant public routes.

## Work units

| ID | Owner | Method | Dependencies | Write scope | Proof | Status |
|---|---|---|---|---|---|---|
| Research | scout | research | none | review document | dated primary sources, X links, actionable findings | ACCEPTED |
| Source audit | reviewer | review | none | none | five verified source gaps and sealed holdout | ACCEPTED |
| Website audit | scout | review | none | isolated portal source | source map, browser checks and public readback | ACCEPTED |
| Build | MAIN | build | audited findings | listed source/docs/tests | regression and existing gates | ACCEPTED |
| Verification | MAIN + reviewer | release review | Build | evidence/release docs | 125 tests, sealed holdout, actual artifact readback; independent review accepted | ACCEPTED |
| Release | MAIN | project native | Verification | release refs and scoped skills website | GitHub release records remote readback | RUNNING |

Checkpoint: worktree from main `d94dd05`; fifteen skills retained. Frozen source
passes 125 deterministic checks, four independent holdout cases and an actual
non-Git artifact task. Astra/Luna probes passed; Claude is blocked by organization
access. Final independent release review passed; publication remains. The GitHub
release will record publication and CI evidence after this source is committed.

Scope update: sourced attribution is permitted only in dated review documents;
operational-branding and public-value scans remain enforced with a regression.
Website metadata must preserve fresh public content and add only Skills entries.
Native goal creation is not required or requested for this run; this file owns progress.
