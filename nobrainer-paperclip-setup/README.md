# nobrainer-paperclip-setup

Cross-platform installer and antifragile orchestrator for
[Paperclip](https://github.com/paperclipai/paperclip) plus a read-only Jira
ticket ingestion routine that converts assigned tickets into agent work and
produces per-ticket HTML reports for human review.

- **Agents NEVER write to Jira**
- **Agents NEVER push commits or open PRs**
- **All proposed actions land in an HTML report; humans execute them**

Works on macOS, Windows, and Linux. Zero non-stdlib Python dependencies. Only
the system `python3` (>= 3.10), `git`, and `node` (>= 20) are required.

## Install

```bash
git clone https://github.com/<your-org>/nobrainer-claude-skills.git
pip install -e nobrainer-claude-skills/nobrainer-paperclip-setup
```

Or drop the `nobrainer-paperclip-setup/` directory into
`~/.claude/skills/nobrainer-paperclip-setup/` and invoke via `python -m`.

## Quick start

```bash
# First-run wizard: workspace, timezone, working hours, Paperclip install, .env, first company
python -m nobrainer_paperclip_setup

# Detect host state (always safe, never mutates)
python -m nobrainer_paperclip_setup detect --json

# Add a git repo to a company, allocate 3 agents
python -m nobrainer_paperclip_setup add-repo --company acme /abs/path/to/repo

# Live status dashboard
python -m nobrainer_paperclip_setup status --watch

# Pull assigned Jira tickets and dispatch as Paperclip tasks
# (no-ops outside the configured working hours; pass --force to override)
python -m nobrainer_paperclip_setup ingest --company acme

# Open the latest HTML report
python -m nobrainer_paperclip_setup reports --open
```

## Architecture

```
+----------------------+        +---------------------+
| Jira (read-only,     | <----  | tickets/ingest.py   |
|  HTTPS, GET only)    |        | (working-hours gate)|
+----------------------+        +----------+----------+
                                           |
                                           v
                              +------------+------------+
                              | Paperclip API           |
                              |  /api/companies         |
                              |  /api/agents            |
                              |  /api/tasks             |
                              | (PaperclipAPIError)     |
                              +------------+------------+
                                           |
                                           v
                              +------------+------------+
                              | Per-agent worktree      |
                              | Per-agent browser (CDP) |
                              | (port lock serializes   |
                              |  add-repo / scale)      |
                              +------------+------------+
                                           |
                                           v
                              +------------+------------+
                              | HTML report             |
                              | <logs>/<co>/<repo>/...  |
                              +-------------------------+
```

## Configuration

State and config locations are computed per-OS via `paths.py`:

| Purpose | macOS | Windows | Linux |
|---|---|---|---|
| Config | `~/Library/Application Support/nobrainer-paperclip-setup/` | `%APPDATA%\nobrainer-paperclip-setup\` | `~/.config/nobrainer-paperclip-setup/` |
| State | same + `/state/` | same + `\state\` | same + `/state/` |
| Logs | `~/Library/Logs/nobrainer-paperclip-setup/` | `%LOCALAPPDATA%\nobrainer-paperclip-setup\Logs\` | `~/.local/state/nobrainer-paperclip-setup/logs/` |
| Browser profiles | `~/Library/Application Support/nobrainer-paperclip-setup/browser-profiles/` | `%LOCALAPPDATA%\nobrainer-paperclip-setup\browser-profiles\` | `~/.local/share/nobrainer-paperclip-setup/browser-profiles/` |

`.env` location is asked once during onboarding. The file is auto-added to the
nearest ancestor `.gitignore`. PAT / token prompts use `getpass.getpass`, so
secrets never echo to the terminal and never land in shell history.

## Read-only Jira contract

Three-layer enforcement in `policies/read_only_jira.py` and `jira/rest_api.py`:

1. **Tool allowlist** filters out anything matching `*create*`, `*update*`,
   `*transition*`, `*add_*`, `*delete*`, `*move*`, `*post_*`, `*put_*`,
   `*patch_*`, `*comment*`, `*assign*`, `*worklog*`, `*archive*`, `*link*`,
   `*vote*`, `*watch*`, `*clone*`, `*upload*`, `*close*`, `*resolve*`,
   `*reopen*`, `*flag*`, `*subscribe*`, `*publish*`.
2. **System prompt clause** prepended to every agent prompt:
   > ABSOLUTE RULES - NEVER VIOLATE:
   > 1. You MUST NOT write to Jira (no comments, transitions, attachments, field updates).
   > 2. You MUST NOT push to remote, create PRs, or merge branches.
   > 3. You MAY read ticket data from the local cache at the path provided.
   > 4. You MAY work inside the provided worktree only.
   > 5. You MUST propose next actions in the HTML report - do not execute them.
3. **Runtime subclass guard**: `JiraRestClient.__init_subclass__` raises if any
   subclass defines a method starting with `post_`, `put_`, `delete_`,
   `patch_`, `create_`, `update_`, `add_`, or `remove_`. A mutating subclass
   cannot be imported.

The REST client (`jira/rest_api.py`) only uses GET, and rejects `http://`
base URLs unless `JIRA_ALLOW_HTTP=1` is set. Grep for `method=` or `data=`
to confirm no mutating verbs exist.

## CLI reference

```
python -m nobrainer_paperclip_setup [-h]
    {detect,companies,memory,add-repo,scale,status,verify,
     teardown,health,ingest,reports,relogin,backups-gc} ...
```

Notable flags:

- `ingest --force` bypasses the working-hours / working-days / timezone gate.
- `ingest --strict` exits with status 1 if any item is skipped.
- `backups-gc` exits with status 1 if any unlink fails or the target directory
  is refused by the backup-shape guard.
- `scale COMPANY REPO DELTA` is **additive** (signed delta), not target count.
  `scale c r +2` then `scale c r +2` results in 4 new agents. Use a negative
  delta (`scale c r -N`) to remove agents.

Run `python -m nobrainer_paperclip_setup <subcommand> --help` for full flags.

## Antifragility

- **Paperclip server**: KeepAlive scheduler entry (launchd / schtasks /
  systemd) survives reboots and crashes.
- **Env-watcher**: per-repo cron pings every URL every 2 min, SSRF-hardened
  (no private / link-local / loopback IPs except an explicit localhost
  allowlist), redirects disabled.
- **Backups GC**: global singleton scheduler, every 6h, retains 48h, keeps
  min 1. Refuses to run unless the target directory looks like a Paperclip
  backup dir (`.sql/.gz/.zip/.dump` files or `backup-*` prefix) and is
  under `$HOME`.
- **Working-hours gate**: `ingest` no-ops outside the configured window;
  `ingest --force` overrides.
- **Idempotency**: `add-repo` and `teardown` are idempotent and safely
  re-runnable. `scale` is additive (signed delta) and is **not**
  idempotent.
- **Per-iteration rollback in `add-repo`**: if provisioning fails on
  agent N, agents 0..N-1 are kept; agent N is rolled back (Paperclip
  agent deleted, worktree removed, profile removed). Re-run `add-repo`
  to continue.
- **Quarantine for broken JSON**: corrupt `state.json` / `preferences.json`
  / ticket snapshots are renamed `<file>.broken-<ts>` with a stderr
  warning; defaults are used and the process continues.
- **Structured Paperclip errors**: `PaperclipAPIError(kind, status)` is
  raised instead of silent `None` returns.
- **Cross-process port lock**: `lock.py` serializes CDP port allocation
  and state writes across concurrent `add-repo` / `scale` runs
  (`fcntl` on POSIX, `msvcrt` on Windows).
- **Atomic writes**: every state mutation goes through
  `paths.atomic_write_json` / `atomic_write_text` (temp + `fsync` +
  `os.replace`, Windows-aware retry on `PermissionError`).

## Security model

- Bearer-token allowlist: `PaperclipAPI` only attaches its `Authorization`
  header when the target host is loopback (`localhost`, `127.0.0.1`, `::1`,
  `0.0.0.0`).
- HTTPS-only Jira REST (override: `JIRA_ALLOW_HTTP=1`).
- Read-only Jira runtime subclass guard.
- Scheduler label regex validation (`^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`).
- Windows scheduler uses PowerShell `-EncodedCommand` (UTF-16-LE +
  base64) instead of writing `.ps1` files with interpolated strings.
- Env-watcher SSRF guard, redirects disabled.
- HTML report URLs restricted to `http(s)` / `mailto` / relative / anchor.
- Evidence files restricted to direct filenames under `evidence_dir`,
  no traversal, no symlink escape.
- Backups dir-shape guard prevents GC against unrelated directories.
- `getpass` for all secret prompts.
- **Supply-chain cooldown for npm**: every npm/npx install (Paperclip server
  onboarding, opencode CLI install, the Paperclip KeepAlive scheduler
  command) pins to the latest version published >= 7 days ago. Resolution
  goes through `npm_safe.py` (`npm view <pkg> time --json` -> highest
  semver whose publish date <= `now - 7 days`). If no version is old enough
  or the registry is unreachable, the install is refused; there is no
  automatic bypass. Emergency override: `NPM_SAFE_BYPASS=1` (loud stderr
  warning). Do not set this unless you have an independent reason to trust
  today's release.

## Installing opencode / re-running paperclip onboard

```bash
python -m nobrainer_paperclip_setup install opencode      # npm install -g opencode-ai@<safe>
python -m nobrainer_paperclip_setup install paperclip     # re-run npx paperclipai onboard
python -m nobrainer_paperclip_setup install --check       # status of both
```

The onboarding wizard also offers to install `opencode` when the default
backend is `opencode-copilot` and the binary is missing.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `detect` reports `paperclip: down` | `python -m nobrainer_paperclip_setup` and accept the onboarding prompt to install via `npx paperclipai onboard --yes`. |
| Browser binary not found | Install Chrome / Edge / Brave; re-run `detect`. |
| `add-repo` fails with "Not enough free CDP ports" | Older agents are listening on the pool; teardown an unused repo first. |
| Jira ingest returns 0 issues | Run `python -m nobrainer_paperclip_setup companies list`; verify backend, server URL (`https://`), and that the PAT is set in `.env`. |
| `ingest` exits immediately doing nothing | You are outside `preferences.working_hours` / `working_days`. Use `ingest --force` to override. |
| `ingest --strict` exited 1 | A ticket was skipped (auth, parse, routing, or dispatch). Check `<logs>/<company>/ingest-<ts>.log`. |
| `JiraRestClient` raises "http base url rejected" | The Jira URL is `http://`; switch to `https://` or set `JIRA_ALLOW_HTTP=1` for a local proxy. |
| `backups-gc` exits 1 with "refused" | Target directory does not look like a Paperclip backup dir or is outside `$HOME`. Point at the correct path. |
| `state.json` quarantined as `.broken-<ts>` | Disk corruption or interrupted write. Inspect the broken file; defaults were re-created. |
| Agent did not produce a report | Check `<logs>/<company>/<repo>/<action>-<ts>.log`. |

## Contributing

Pull requests welcome. Keep the stdlib-only constraint: no new runtime
dependencies. Type hints on every signature. Atomic writes for any file
mutation (use `paths.atomic_write_json` / `atomic_write_text`). No `print()`
to stdout for errors -- use `sys.stderr`.

## License

MIT.
