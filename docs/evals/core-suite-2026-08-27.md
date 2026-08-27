# Core suite evaluation — 2026-08-27

Status: `LOCAL_CANDIDATE / OWNER_MERGE_GATE`

This is a bounded `nobrainer-autoimprove` evaluation of the curated public
suite. It supports a local merge decision only. It does not prove production,
marketplace, cross-client UI or buyer usefulness.

## Frozen candidate

The candidate contains exactly nine discoverable skills:

1. `nobrainer-ultra`
2. `nobrainer-sessions`
3. `nobrainer-spec-driven-development`
4. `nobrainer-wiki`
5. `nobrainer-browser`
6. `nobrainer-autoimprove`
7. `nobrainer-decide`
8. `nobrainer-rca`
9. `nobrainer-review`

The digest covers all 54 tracked, present repository files except this report,
so recording the result does not mutate the tested artifact. Starting with an
empty SHA-256 state, process Git paths in lexical order and append the UTF-8
path, one NUL byte, the raw file bytes and one NUL byte for each file:

```text
CANDIDATE: nine-skill-suite-v1
SHA256: 68838cfc384676fefa75b91eb24e89b0d4a0bdd86b0f8dcac0775b7137e17148
```

Earlier 19-skill freezes and their 23-test holdout remain available in Git
history, but are superseded. They are not evidence for this reduced candidate.

## Why these nine

- `nobrainer-ultra` owns project setup, intent normalization, lightweight
  routing, anti-slop rules and the escalation path to task-specific skills.
- `nobrainer-sessions` owns visible multi-session coordination and audited
  handoffs.
- `nobrainer-spec-driven-development` owns durable specifications when the
  work benefits from SDD.
- `nobrainer-wiki` owns setup, retrieval, capture and tidy modes for durable
  project knowledge.
- `nobrainer-browser` owns browser inspection, approved CDP attachment and
  trace analysis through Playwright CLI.
- `nobrainer-autoimprove`, `nobrainer-decide`, `nobrainer-rca` and
  `nobrainer-review` own learning, consequential decisions, root-cause analysis
  and evidence-gated review respectively.

Retired helpers were either folded into those owners or removed as broad,
stack-specific or duplicate behavior. Missing task specialists may be used
temporarily through `skills.sh`; they do not become permanent dependencies
without review.

## Hard gates

- active inventory is exactly the nine canonical skills;
- every `SKILL.md` has portable frontmatter and a tested `nb-*` alias trigger;
- `AGENTS.md` and `CLAUDE.md` are byte-identical and carry the same lightweight
  quality, safety and learning contract;
- installation defaults to all nine, supports an exact subset, refuses foreign
  targets and migrates only recognized legacy links with explicit consent;
- worker status is audit input, not proof; consequential actions retain an
  owner gate;
- local secret scanning passes without broad allowlists;
- no P0/P1 review finding remains open.

Any hard-gate failure rejects the candidate.

## Review corrections included

- Reduced the active inventory from nineteen skills to nine and removed more
  than four thousand lines of duplicate review/browser/wiki machinery.
- Folded wiki add/get/tidy behavior into one mode-based owner.
- Replaced several overlapping review skills and custom harnesses with one
  concise `nobrainer-review` contract.
- Removed the last archived `SKILL.md`; the entire repository now contains
  only the nine canonical skill entrypoints.
- Added `playwright-cli -> nobrainer-browser` migration so an old browser skill
  cannot remain a competing trigger.
- Made canonical-target migration map-driven across both previous root and
  `skills/` layouts, including every retired name and renamed predecessor.
- Replaced check-then-unlink alias migration with an atomic, recoverable claim:
  a link changed after preflight is restored or preserved for manual recovery,
  never silently deleted.
- Made restore atomic and no-overwrite for both symlinks and non-symlink entries
  on the supported platforms, with concurrent replacement regression tests.
- Fixed both defects from the first independent final-diff review: relative
  legacy links retain their original resolution base, and a raced foreign file
  or directory is rejected before the installer moves it.
- Added regressions for relative links and foreign-directory replacement, plus
  migration of the removed `nobrainer-memory-memsearch` predecessor.
- Fixed both findings from the second independent final-diff review: a foreign
  file or directory moved in the snapshot-to-claim window is restored without
  overwrite, and the installer now fails closed if its source inventory differs
  from the explicit nine-skill allowlist.
- Bound legacy ownership validation and fingerprinting to the same symlink entry,
  covering a replacement between target resolution and fingerprint capture.
- Narrowed `nobrainer-review` to the final evidence gate so ordinary
  implementation review remains owned by the current client or Superpowers.
- Replaced the stale OpenCode package SHA with a deliberately non-runnable
  reviewed-commit placeholder and made the Gitleaks gate scan the exact staged
  candidate.
- Added a checksum-pinned Gitleaks current-tree scan to Linux CI, disabled inline
  `gitleaks:allow` bypasses, and unified the managed project-instruction marker
  as `NOBRAINER-WORKFLOW`.

## Local verification

- `python3 scripts/validate_skills.py`: PASS;
- `python3 scripts/validate_skills.py --suite`: PASS;
- `python3 -m unittest discover -s tests -v`: 50/50 PASS;
- `python3 -m py_compile scripts/*.py tests/*.py`: PASS;
- all Python helpers parse with the Python 3.11 grammar used by CI: PASS;
- system `quick_validate.py`: 9/9 active skills valid;
- `actionlint` v1.7.12, downloaded from its official GitHub release and
  verified against the checksum published with that release: PASS;
- `gitleaks` v8.30.1 with `.gitleaks.toml` and inline allow comments disabled:
  no leaks in the worktree or exact staged candidate;
- the synthetic staged-secret probe is rejected by the installed Gitleaks CLI;
- `git diff --cached --check`: PASS;
- `AGENTS.md` equals `CLAUDE.md`: PASS.

The Python compile step creates ignored `__pycache__` files. Those local caches
were removed before the directory secret scan so the intentionally synthetic
test token embedded in bytecode was not mistaken for repository content.

## Remaining gates and limits

- Two independent final-diff review rounds found four actionable installer
  defects in total; all are fixed with regression coverage. Final post-fix
  re-review: `PASS / no actionable findings`.
- GitHub Actions on the pushed candidate: `PENDING`.
- Owner-authorized merge and default-branch readback: `PENDING`.
- No production, marketplace, authenticated buyer or cross-client UI run is
  implied by these local checks.

Rollback is Git history: revert the candidate merge or restore a retired skill
from the pre-curation commit. Installer migrations also preserve or restore a
legacy link when a write fails.
