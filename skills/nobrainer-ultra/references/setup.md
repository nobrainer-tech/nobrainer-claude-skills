# Setup and upgrade protocol

Use this reference when the owner asks to set up, install, upgrade, repair, or
reconcile NoBrainer workflows in a project. The same protocol applies after an
earlier setup; never assume installed files still match current requirements.

## 1. Discover before writing

Read the repository root, nearest instructions, dirty state, active client
files, skill locations, current specs/plans/wiki, test commands and installed
plugin capabilities. Classify each desired component as:

- `CURRENT` — present, canonical and verified;
- `DRIFTED` — present but stale or contradictory;
- `MISSING` — justified but absent;
- `NOT_NEEDED` — ceremony without a current use;
- `OWNER_GATE` — requires login, marketplace UI, credentials, consequential
  overwrite or another explicit decision.

Do not create SDD, wiki, session registry, lease files or client adapters merely
because a template exists.

## 2. Reconcile project instructions

Preserve existing `AGENTS.md`, `CLAUDE.md` and client-managed blocks. Add or
update one marked NoBrainer block only when durable routing is missing. Keep it
short: point non-trivial work to `nobrainer-ultra`, state owner gates and name
the repository's canonical spec/state/test locations. Link to project docs;
never paste the complete skill protocols into every repository.

If multiple instruction files must carry identical content, compare them byte
for byte after the change or document why their scopes differ.

## 3. Install one portable NoBrainer source

Prefer the current client's native plugin or Agent Skills mechanism. If using a
local checkout, dry-run `scripts/install_skills.py`, review every target, then
apply. Existing different targets are conflicts, not overwrite candidates.
Read back the loaded skill list after restarting the client.

An install exit code or files on disk prove installation only; they do not prove
automatic routing. Use the clean-session acceptance protocol in
`docs/COMPATIBILITY.md` when that repository document is available.

## 4. Reconcile official Superpowers

Superpowers is an external implementation-method dependency, not bundled
NoBrainer content. Resolve its current official instructions from:

https://github.com/obra/superpowers

Use the exact native channel supported by the active client. Prefer an official
marketplace listing when available; otherwise follow the current upstream
install document. Do not guess commands from memory, pin an unverified version,
copy its skill folders into NoBrainer, or keep older renamed wrappers.

Installing a plugin is a machine/account write. A direct owner request to set
up NoBrainer with Superpowers authorizes the reversible install attempt, but UI
login, trust prompts, credentials, paid actions and broad config replacement
remain owner gates. If the current agent cannot operate the native installer,
return one exact `OWNER_ACTION_REQUIRED` step rather than claiming installation.

After installation, verify:

- the source is official and the resolved version is reported;
- the client lists the expected Superpowers skills;
- no stale local wrapper owns the same trigger;
- a clean-session smoke test selects the relevant implementation skill;
- uninstall or rollback instructions are known.

## 5. Choose only justified project artifacts

- Add SDD when contracts, dependencies, migration, risk or resumability justify
  it.
- Add a wiki only for durable knowledge that will be queried across tasks.
- Add visible sessions only for handoff, isolation, resume, independent work or
  warm specialist reuse.
- Keep execution state separate from specs, workflow rules, reports and wiki.

## 6. Close with readback

Report:

```text
MODE: SETUP | UPGRADE | REPAIR
NOBRAINER_SOURCE:
CLIENTS_CONFIGURED:
SUPERPOWERS_SOURCE:
SUPERPOWERS_VERSION:
PROJECT_INSTRUCTIONS:
SDD: CURRENT | CREATED | UPDATED | NOT_NEEDED
WIKI: CURRENT | CREATED | UPDATED | NOT_NEEDED
SESSIONS: CURRENT | CREATED | UPDATED | NOT_NEEDED
STATIC_CHECKS:
RUNTIME_CHECKS:
OWNER_ACTION_REQUIRED:
UNVERIFIED:
ROLLBACK:
```

Do not mark setup complete while required runtime discovery or an owner action is
unknown. Separate a locally prepared configuration from a verified live client.
