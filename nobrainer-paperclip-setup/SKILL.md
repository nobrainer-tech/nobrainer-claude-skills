---
name: nobrainer-paperclip-setup
description: Cross-platform installer and antifragile orchestrator for Paperclip plus read-only Jira ticket ingestion. Bootstraps the local Paperclip server, manages companies and repos, allocates per-agent git worktrees, browser pool (Chrome/Edge/Brave with CDP), schedules watchdogs (env-watcher per repo, backups-gc globally), ingests assigned Jira tickets during configured working hours, dispatches them to the right agent, and produces self-contained HTML reports for human review. Agents NEVER write to Jira and NEVER push commits or open PRs. Works on macOS, Windows, Linux. No external Python dependencies, no hardcoded users or paths.
---

# nobrainer-paperclip-setup

A dynamic, cross-platform skill that stands up an antifragile Paperclip
environment and feeds it Jira tickets. Self-configuring: it inspects the host,
asks what is missing, and installs everything it needs. Designed to be shared
publicly: no personal data, no machine-specific paths.

## Triggers

Activate when the user says:

- `nobrainer-paperclip-setup`, `paperclip-setup`
- "set up paperclip", "install paperclip", "configure paperclip"
- "add company to paperclip", "add repo to paperclip", "scale paperclip agents"
- "paperclip status", "what are the paperclip agents doing"
- "verify paperclip", "verify paperclip setup"
- "teardown paperclip", "remove paperclip for <repo>"
- "antifragile paperclip", "paperclip backups gc"
- "ingest jira tickets", "pull jira to paperclip"
- "open paperclip reports"

## What it does

1. **Onboarding wizard** (first run only):
   - Detects the orchestrator workspace (`cwd`) and optionally installs the
     `nobrainer-memory` skill there.
   - Interviews the user for timezone, working hours, working days, max
     concurrent tickets, default backend, default browser.
   - Verifies Paperclip server is up (`http://localhost:3100/api/health`); if
     not, runs `npx paperclipai onboard --yes` and installs a KeepAlive
     scheduler entry so it survives reboots.
   - Asks for `.env` location and persists it. Adds `.env` to nearest
     `.gitignore`.
   - Lets the user add companies via `POST /api/companies`.
   - PAT / token prompts use `getpass.getpass`: no terminal echo, no shell
     history entry.
2. **Per-repo provisioning** (`add-repo`):
   - Allocates N agents per repo via the shared
     `provisioning.provision_agent(...)` helper (also used by `scale`).
   - Port allocation and state writes are serialized across concurrent
     `add-repo` / `scale` runs by a cross-platform exclusive file lock
     (`lock.py`, `fcntl` on POSIX, `msvcrt` on Windows).
   - Each agent gets: a git worktree (`<repo>-<company>-agent-<N>`), a CDP port
     from pool 19840-19899, a browser profile (Chrome/Edge/Brave), a backend
     config (codex-cli or opencode-copilot), a Paperclip agent registration.
   - Installs an env-watcher cron (every 2 min) and a global backups-gc cron
     (every 6h, keep last 48h).
3. **Read-only Jira ingestion** (`ingest`):
   - Gated by working hours: `_within_working_hours()` consults
     `preferences.working_hours`, `working_days`, and `timezone`. Outside the
     window the ingest cycle no-ops. `ingest --force` bypasses the gate.
   - Per company, queries Jira via Atlassian MCP backend (instructions for the
     orchestrator LLM to drive MCP calls) or REST API (HTTPS, GET only).
   - Caches snapshots; only dispatches new / changed tickets.
   - Routes each ticket to an agent via `routing_strategy` (round-robin /
     least-loaded / by-type). Round-robin uses a persistent
     `_routing_cursor` in `state.json`.
   - Sends a Paperclip task with a system prompt that injects the read-only
     Jira clause.
4. **HTML reports** (`reports`):
   - Each ticket gets `<logs>/<company>/<repo>/tickets/<KEY>/report.html` with
     description, AC coverage, files changed, tests, evidence screenshots,
     proposed next action (e.g. PR command), and agent metadata.
5. **Verification** (`verify`):
   - Emits a markdown plan listing exact `mcp__playwright__*` tool calls the
     orchestrator LLM should execute. Falls back to a standalone `agent-browser`
     CLI if Playwright MCP is unreachable.

## Hard rules (NEVER violate)

- Agents MUST NOT write to Jira (no comments, transitions, attachments, field
  updates). Enforced by tool allowlist + system prompt clause + runtime
  subclass guard on the REST client.
- Agents MUST NOT push to remote, create PRs, or merge branches.
- Agents MAY read ticket data from the local cache and work inside their
  assigned worktree only.
- All proposed next actions go into the HTML report; the human executes them.

## Architecture

```
<skill_dir>/
  SKILL.md
  README.md
  pyproject.toml
  templates/
    agent_system_prompt.md
    ticket_report.html
    env_watcher.py
    scheduler/
      launchd.plist.tmpl
      systemd.service.tmpl
      systemd.timer.tmpl
      task_scheduler.xml.tmpl
  nobrainer_paperclip_setup/
    __init__.py
    __main__.py             # CLI entry: python -m nobrainer_paperclip_setup
    paths.py                # cross-platform path resolver + atomic_write_json/text + slugify
    lock.py                 # cross-platform exclusive file lock (fcntl / msvcrt)
    preferences.py          # preferences.json CRUD
    companies.py            # company CRUD in preferences.json
    state.py                # per-(company,repo) state JSON CRUD
    wizard.py               # interactive prompts
    memory.py               # bootstrap nobrainer-memory in workspace
    credentials.py          # .env reader/writer, PAPERCLIP_TOKEN_<COMPANY>
    detect.py               # host state snapshot -> JSON
    browser.py              # Chrome/Edge/Brave detection + CDP launcher
    browser_pool.py         # per-agent port + profile allocation (port lock)
    worktree.py             # git worktree helpers
    backend.py              # codex-cli vs opencode-copilot config + prompt
    backups.py              # GC backups older than 48h, keep min 1, dir-shape guard
    verify.py               # Playwright MCP plan + agent-browser fallback
    paperclip_api.py        # HTTP client for local Paperclip + PaperclipAPIError + host whitelist
    npm_safe.py             # 7-day supply-chain cooldown around npm/npx
    opencode_install.py     # `npm install -g opencode-ai` via npm_safe
    paperclip_install.py    # npx paperclipai onboard --yes via npm_safe + KeepAlive
    provisioning.py         # provision_agent(...) shared by add-repo and scale
    interactive.py          # menu + first-run onboarding wizard
    scheduler/
      __init__.py           # selects backend by sys.platform
      base.py               # abstract Scheduler + ScheduleSpec (label validation)
      launchd.py            # macOS LaunchAgents
      task_scheduler.py     # Windows schtasks.exe (PowerShell -EncodedCommand)
      systemd_user.py       # Linux systemd --user
    jira/
      __init__.py
      client.py             # abstract JiraClient
      atlassian_mcp.py      # orchestrator-driven MCP bridge
      rest_api.py           # GET-only REST v3 client (HTTPS-only, subclass guard)
      selector.py           # pick backend by company.jira.backend
    policies/
      __init__.py
      read_only_jira.py     # READ_ONLY_CLAUSE, filter_tools(), inject_into_prompt()
    tickets/
      __init__.py
      store.py              # local snapshot cache
      routing.py            # pick_agent() - round-robin via persistent cursor
      ingest.py             # main poll-and-dispatch loop (working-hours gate)
      report.py             # render(ticket, agent_output, evidence_dir) -> HTML
    actions/
      __init__.py
      add_repo.py
      scale.py
      status.py
      verify.py
      teardown.py
      health.py
      ingest.py
      reports.py
      memory.py
      companies.py
```

## Naming conventions

| Concept | Format |
|---|---|
| Git branch | `<company>/<TICKET-KEY>` |
| Worktree | `<repo_path>-<company>-agent-<N>` |
| Scheduler label | `dev.nobrainer.paperclipsetup.<company>.<repo>.<service>` |
| Browser profile | `<company>-<repo>-agent-<N>` |
| Paperclip agent | `<company>-<repo>-agent-<N>` |
| Report path | `<logs>/<company>/<repo>/tickets/<KEY>/report.html` |
| State file | `<state>/<company>__<repo>.json` |
| .env company token | `PAPERCLIP_TOKEN_<COMPANY_UPPER>` |
| .env Jira PAT | `JIRA_PAT_<COMPANY_UPPER>` |

`paths.slugify(value, *, case='lower', sep='-')` is the canonical slugifier.
Two intentional exceptions exist for backwards compatibility with on-disk
state files: `companies._slug` and `tickets/store._safe_key` keep their
narrower legacy regex so existing state keys remain stable. Do not unify them
without a migration.

## State & config locations

Computed via `paths.py`:

| Purpose | macOS | Windows | Linux |
|---|---|---|---|
| Config | `~/Library/Application Support/nobrainer-paperclip-setup/` | `%APPDATA%\nobrainer-paperclip-setup\` | `~/.config/nobrainer-paperclip-setup/` |
| State | same + `/state/` | same + `\state\` | same + `/state/` |
| Logs | `~/Library/Logs/nobrainer-paperclip-setup/` | `%LOCALAPPDATA%\nobrainer-paperclip-setup\Logs\` | `~/.local/state/nobrainer-paperclip-setup/logs/` |
| Browser profiles | `~/Library/Application Support/nobrainer-paperclip-setup/browser-profiles/` | `%LOCALAPPDATA%\nobrainer-paperclip-setup\browser-profiles\` | `~/.local/share/nobrainer-paperclip-setup/browser-profiles/` |
| `.env` | user-chosen at first run; default `<cwd>/.env` |

## Defaults

- **CDP port pool**: `19840-19899` (60 slots). Skipped if already listening or
  allocated in any `state/*.json`. Allocation is wrapped in the cross-process
  file lock (`lock.py`) so concurrent `add-repo` / `scale` cannot collide.
- **Scheduler label prefix**: `dev.nobrainer.paperclipsetup`.
- **Backup retention**: 48h, min 1 always kept, GC every 6h.
- **Env-watcher interval**: 2 minutes.
- **Idempotency**: `add-repo` and `teardown` are idempotent (read state first,
  no-op if already in target state). `scale` is **additive**: `scale c r +2`
  followed by another `scale c r +2` results in 4 new agents, not 4 total.
  Use a negative delta (`scale c r -N`) to remove agents.

## Read-only Jira contract

Two-layer policy enforcement plus a runtime structural guard:

1. **Tool allowlist** (`policies/read_only_jira.py`) filters out anything
   matching `*create*`, `*update*`, `*transition*`, `*add_*`, `*delete*`,
   `*move*`, `*post_*`, `*put_*`, `*patch_*`, `*comment*`, `*assign*`,
   `*worklog*`, `*archive*`, `*link*`, `*vote*`, `*watch*`, `*clone*`,
   `*upload*`, `*close*`, `*resolve*`, `*reopen*`, `*flag*`, `*subscribe*`,
   `*publish*`.
2. **System prompt clause** prepended to every agent prompt (see clause text
   in `policies/read_only_jira.py`).
3. **Runtime subclass guard**: `JiraRestClient.__init_subclass__` raises at
   class-definition time if any subclass defines a method whose name starts
   with `post_`, `put_`, `delete_`, `patch_`, `create_`, `update_`, `add_`,
   or `remove_`. You cannot accidentally ship a mutating subclass.
4. **HTTPS enforcement**: `JiraRestClient` refuses any `http://` base URL
   unless `JIRA_ALLOW_HTTP=1` is set in the environment (intended only for
   local proxy debugging).

The REST client uses GET only. Grep for `method=` or `data=` to confirm.

## Backends

| Backend | Paperclip adapter | Requires |
|---|---|---|
| `codex-cli` | `codex_local` | `codex` in PATH, OpenAI key in `.env` |
| `opencode-copilot` | `opencode_local` | `opencode` in PATH, `gh auth status` shows Copilot |

## Scheduler

- `ScheduleSpec.__post_init__` validates the scheduler label against
  `^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`. Invalid labels raise immediately
  (prevents shell injection through launchd / schtasks / systemd unit names).
- **Windows TaskScheduler** wraps commands as PowerShell `-EncodedCommand`:
  the wrapper script is UTF-16-LE encoded then base64-encoded and passed as
  a single argv element. No `.ps1` files are written, no string interpolation
  into a shell.

## Env-watcher (`templates/env_watcher.py`)

- SSRF guard: refuses any URL whose scheme is not `http(s)`, refuses
  private / link-local / loopback IPs except an explicit localhost allowlist.
- Auto-redirects are disabled; the watcher records the redirect target
  instead of following it.

## HTML reports (`tickets/report.py`)

- All user-controlled strings are HTML-escaped.
- `_safe_url(...)` accepts only `http(s)://`, `mailto:`, relative paths, and
  in-page anchors. Anything else is dropped.
- `_safe_evidence_files(...)` only links direct filenames inside the
  evidence directory: no `..`, no path separators, no symlinks escaping
  `evidence_dir`.

## Backups (`backups.py`)

- `_looks_like_backup_dir(...)` refuses to GC unless the target directory
  contains files matching `.sql`, `.gz`, `.zip`, or `.dump`, **or** has a
  `backup-*` name prefix, **and** lives under `$HOME`. Catastrophic
  mis-pointed GCs against unrelated directories are blocked at the gate.

## Entry points

```
python -m nobrainer_paperclip_setup                # menu / onboarding
python -m nobrainer_paperclip_setup detect [--json]
python -m nobrainer_paperclip_setup companies {list,add}
python -m nobrainer_paperclip_setup memory {install,status,uninstall}
python -m nobrainer_paperclip_setup add-repo [--company SLUG] [REPO_PATH]
python -m nobrainer_paperclip_setup scale COMPANY REPO DELTA          # additive, signed
python -m nobrainer_paperclip_setup status [--company SLUG] [--repo NAME] [--watch] [--json]
python -m nobrainer_paperclip_setup verify COMPANY REPO [--fallback agent-browser|manual]
python -m nobrainer_paperclip_setup teardown COMPANY REPO [--yes]
python -m nobrainer_paperclip_setup health [--company SLUG] [--repo NAME]
python -m nobrainer_paperclip_setup ingest [--company SLUG] [--json] [--force] [--strict]
python -m nobrainer_paperclip_setup reports [--company SLUG] [--repo NAME] [--open]
python -m nobrainer_paperclip_setup relogin COMPANY REPO [--agent N]
python -m nobrainer_paperclip_setup backups-gc [--retention-hours N] [--dry-run]
python -m nobrainer_paperclip_setup install {opencode,paperclip} [--cooldown-days N] [--json]
python -m nobrainer_paperclip_setup install --check [--json]
```

`detect --json` is always safe to call: pure read, no mutations,
deterministic JSON output.

CLI flag notes:
- `ingest --force` bypasses the working-hours / working-days / timezone gate.
- `ingest --strict` exits with status 1 if any item is skipped (auth, parse,
  routing, dispatch). Default behavior logs and continues.
- `backups-gc` exits with status 1 if any `unlink` fails or the target
  directory is refused by `_looks_like_backup_dir`.

## Antifragility playbook

- **Paperclip server**: KeepAlive scheduler entry (launchd / schtasks /
  systemd) restarts the server after reboots and crashes.
- **Env-watcher**: per-repo cron pings every URL every 2 min, writes status
  JSON. SSRF-hardened, redirect-disabled.
- **Backups GC**: global singleton scheduler, every 6h, retains 48h, keeps
  min 1, dir-shape guarded.
- **Working-hours gate**: `tickets/ingest.py::_within_working_hours()`
  no-ops the ingest cycle outside `preferences.working_hours` /
  `working_days` / `timezone`. Use `ingest --force` to override manually.
- **Per-iteration rollback in `add-repo`**: agents are provisioned in a
  loop; if step N fails, agents 0..N-1 are persisted and the failing
  agent is rolled back (Paperclip agent deleted, worktree removed,
  profile removed). Re-run `add-repo` to continue from where it stopped.
- **Quarantine for broken JSON**: a corrupt `state.json`, `preferences.json`,
  or ticket snapshot is renamed to `<file>.broken-<ts>` with a warning to
  stderr; defaults are used and the process continues. The original is
  preserved for forensic review.
- **Structured Paperclip errors**: `paperclip_api.PaperclipAPIError(kind,
  status)` is raised instead of silent `None` returns. Reviewers and
  callers must handle the error explicitly.

## What this skill does NOT do

- Does not install Codex CLI (use `codex:setup` or upstream docs).
- **opencode** can be installed via `install opencode` or accepted during the
  onboarding wizard; the install is routed through the 7-day supply-chain
  cooldown (see "Supply-chain protection" below).
- Does not write business logic for individual agents (see `paperclip-master`,
  `paperclip-ceo`, `paperclip-focus`).
- Does not log you into apps inside browser profiles - opens the window and
  waits for you to confirm login is complete.
- Does not write to Jira (read-only by construction).
- Does not push commits or open PRs (agents produce HTML reports only).
- Does not modify your shell rc, PATH, or global git config.

## Security model

- **Token host whitelist**: `PaperclipAPI` only attaches its bearer
  `Authorization` header when the target URL host is loopback
  (`localhost`, `127.0.0.1`, `::1`, `0.0.0.0`). Cross-host calls travel
  without credentials.
- **HTTPS-only Jira REST**: `http://` rejected unless `JIRA_ALLOW_HTTP=1`.
- **Read-only Jira runtime guard**: `__init_subclass__` blocks mutating
  method names at class-definition time (see Read-only Jira contract).
- **Scheduler label validation**: regex-validated to prevent shell injection
  via launchd / schtasks / systemd unit names.
- **PowerShell -EncodedCommand on Windows**: no `.ps1` strings interpolated.
- **Env-watcher SSRF guard**: only http(s), no private / link-local /
  loopback (except explicit localhost), redirects disabled.
- **HTML report safe URL filter**: links restricted to http(s) / mailto /
  relative / anchor.
- **Evidence symlink filter**: files in HTML report restricted to direct
  filenames in `evidence_dir`, no traversal, no symlink escape.
- **Cross-process port lock**: `lock.py` serializes CDP port allocation and
  state writes across concurrent `add-repo` / `scale`.
- **Backups dir-shape guard**: `_looks_like_backup_dir` blocks GC against
  unrelated directories.
- **Quarantine over crash**: corrupt JSON files are renamed
  `.broken-<ts>` and defaults are used.
- **`getpass` for secrets**: PAT / token prompts never echo and never enter
  shell history.

### Supply-chain protection (npm 7-day cooldown)

Every npm-driven install this skill triggers pins to the latest version that
was published **at least 7 days ago**. Recent supply-chain incidents
(`chalk`, `debug`, `ua-parser-js`) all weaponised versions that were
hours-to-days old when they hit unsuspecting installers; the cooldown is the
single highest-leverage defence available to a stdlib-only installer.

- Resolution lives in `npm_safe.py`. It runs `npm view <pkg> time --json`,
  sorts versions by publish timestamp, and picks the highest semver whose
  publish date is `<= now - 7 days`.
- Wrapped calls:
  - `npm_safe.run_npx("paperclipai", ["onboard", "--yes"])` — Paperclip
    server onboarding (replaces the previous unpinned `npx paperclipai`).
  - `npm_safe.install_global("opencode-ai")` — opencode CLI install via the
    `install opencode` subcommand and the onboarding wizard.
  - The KeepAlive scheduler entry for the Paperclip server records the
    resolved version, so respawns do not silently slide forward.
- If the registry is unreachable or no version is old enough, an
  `NpmSafeError` is raised and the install is refused. There is no automatic
  bypass; the user must intervene.
- **Emergency escape hatch**: `NPM_SAFE_BYPASS=1` disables the cooldown for
  the current process. A loud stderr warning is emitted whenever this flag
  is active. Do not set it unless you have an independent reason to trust
  today's release of the package.

### `install` subcommand

```
python -m nobrainer_paperclip_setup install opencode    # npm install -g opencode-ai@<safe>
python -m nobrainer_paperclip_setup install paperclip   # re-run npx paperclipai onboard
python -m nobrainer_paperclip_setup install --check     # report installed/version for both
```

All three paths flow through `npm_safe`; the same `--check` data is also
available from the interactive menu item 15 (`install`).

## For LLMs reading this skill

**Invoke when the user wants to:**
- Set up Paperclip from scratch on a new machine
- Add another company or repo to an existing setup
- Scale agents up or down for a repo
- Ingest assigned Jira tickets and produce review-ready HTML reports
- Verify the current setup actually works
- Recover from a crashed MCP server, scheduler, or browser process

**Do not invoke for:**
- Day-to-day Paperclip task management (use `paperclip-master`, `paperclip-ceo`)
- Writing prompts for individual agents (use `prompt-engineer`)
- Installing Codex CLI / opencode binaries themselves

**State files are the single source of truth.** Mutating actions write
`<config>/state/<company>__<repo>.json` through `paths.atomic_write_json`
(or `atomic_write_text`): write to a temp sibling, `fsync`, `os.replace`,
with a Windows-aware retry on `PermissionError`. This is the only sanctioned
write pattern; do not introduce ad-hoc `open(..., 'w')` for state.

**Error contract:** `PaperclipAPI` methods raise
`PaperclipAPIError(kind, status)` on failure (network, non-2xx, parse).
Reviewers and callers must catch and surface these, not assume `None`
means "absent".

**Idempotency contract:** `add-repo` and `teardown` are idempotent and
safely re-runnable. `scale` is **additive** (signed delta) and is **not**
idempotent: running it twice doubles the change. `ingest` is gated by
working hours; use `--force` to override.
