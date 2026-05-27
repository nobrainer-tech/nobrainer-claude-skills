"""Top-level interactive loop and first-time onboarding wizard."""

from __future__ import annotations

import datetime as _dt
import json
import os
import sys
from pathlib import Path
from typing import Callable

from . import (
    backups,
    browser,
    browser_pool,
    credentials,
    detect,
    memory,
    opencode_install,
    paperclip_api,
    paperclip_install,
    paths,
    preferences,
    state,
    wizard,
)
from .actions import (
    add_repo as a_add_repo,
    companies as a_companies,
    health as a_health,
    ingest as a_ingest,
    memory as a_memory,
    reports as a_reports,
    scale as a_scale,
    status as a_status,
    teardown as a_teardown,
    verify as a_verify,
)


def _default_timezone() -> str:
    """Best-effort local-TZ name. Falls back to UTC."""
    try:
        tz = _dt.datetime.now().astimezone().tzinfo
        name = getattr(tz, "key", None) or str(tz)
        return name or "UTC"
    except Exception:  # noqa: BLE001
        return "UTC"


def _install_opencode_interactive() -> None:
    """Install opencode via npm_safe and report verify() outcome to the user."""
    from . import npm_safe

    try:
        result = opencode_install.install()
    except npm_safe.NpmSafeError as exc:
        print(
            f"[opencode] install aborted: {exc}. Install manually with "
            "`npm install -g opencode-ai` once the registry is reachable.",
            file=sys.stderr,
        )
        return
    print(
        f"[opencode] resolved {result['package']}@{result['version']} "
        f"(age_days={result['age_days']}), rc={result['rc']}"
    )
    if result["rc"] != 0:
        print(
            f"[opencode] npm exited with rc={result['rc']}; see {result['log_path']}",
            file=sys.stderr,
        )
        return
    check = opencode_install.verify()
    if check["ok"]:
        print(f"[opencode] verified: {check['binary']} (v{check['version']})")
    else:
        print(
            "[opencode] install reported success but verify() failed. "
            "You can install manually and re-run onboarding.",
            file=sys.stderr,
        )


def _onboard() -> int:
    print("nobrainer-paperclip-setup: first-time onboarding")

    # Collect every answer into a single dict and persist once at the end so
    # other processes never observe a half-configured preferences file.
    draft = preferences.load()

    workspace = Path(os.getcwd())
    if wizard.ask_yes_no(f"Use {workspace} as orchestrator workspace?", default=True):
        draft["orchestrator_workspace"] = str(workspace)
    else:
        picked = wizard.ask_path(
            "Orchestrator workspace path", must_exist=False, default=workspace,
        )
        if picked:
            draft["orchestrator_workspace"] = str(picked)
            workspace = picked

    if not memory.is_memory_installed(workspace):
        if wizard.ask_yes_no("Install nobrainer-memory skill in this workspace?", default=True):
            memory.install_memory(workspace)

    tz_default = _default_timezone()
    tz_value = wizard.ask("Timezone", tz_default) or tz_default
    work_start = wizard.ask("Working hours start (HH:MM)", "08:00") or "08:00"
    work_end = wizard.ask("Working hours end (HH:MM)", "18:00") or "18:00"
    work_days = wizard.ask(
        "Working days (comma-separated)", "mon,tue,wed,thu,fri",
    ) or "mon,tue,wed,thu,fri"
    max_tickets = wizard.ask_int("Max concurrent tickets", 1, 64, 4)
    backend_default = wizard.ask_choice(
        "Default backend",
        ["opencode-copilot", "codex-cli"],
        default="opencode-copilot",
    ) or "opencode-copilot"

    if backend_default == "opencode-copilot" and not opencode_install.is_installed():
        if wizard.ask_yes_no(
            "opencode CLI not found. Install via npm with the 7-day "
            "supply-chain cooldown?",
            default=True,
        ):
            _install_opencode_interactive()

    available = browser.detect_available()
    browser_options = [name for name, p in available.items() if p is not None] or ["chrome"]
    browser_default = wizard.ask_choice(
        "Default browser",
        browser_options,
        default=browser_options[0],
    ) or browser_options[0]

    draft.update({
        "timezone": tz_value,
        "working_hours": {"start": work_start, "end": work_end},
        "working_days": [d.strip().lower() for d in work_days.split(",") if d.strip()],
        "max_concurrent_tickets": max_tickets,
        "backend_default": backend_default,
        "browser_default": browser_default,
    })

    if not paperclip_install.is_running():
        if wizard.ask_yes_no(
            "Paperclip is not running. Install via `npx paperclipai onboard --yes`?",
            default=True,
        ):
            paperclip_install.install_via_npx()
            paperclip_install.wait_for_alive(timeout=120)
        if wizard.ask_yes_no("Install KeepAlive scheduler entry for Paperclip server?", default=True):
            paperclip_install.install_keepalive_scheduler()

    if credentials.get_env_path() is None:
        suggestion = credentials.suggest_env_path(workspace)
        picked = wizard.ask_path(".env file location", must_exist=False, default=suggestion)
        if picked:
            picked.parent.mkdir(parents=True, exist_ok=True)
            if not picked.exists():
                picked.touch()
            credentials.set_env_path(picked)
            credentials.ensure_gitignored(picked)

    draft["onboarded_at"] = paths.now_utc_iso()
    preferences.save(draft)

    print("\nCompanies in Paperclip:")
    api = paperclip_api.PaperclipAPI()
    remote = api.list_companies() if api.health() else []
    for i, c in enumerate(remote, start=1):
        print(f"  {i}) {c.get('slug')}  ({c.get('name')})")

    if wizard.ask_yes_no("Add a new company now?", default=True):
        a_companies.add_cmd()

    print("\nOnboarding complete. Re-run `nobrainer-paperclip-setup` for the menu.")
    return 0


def _do_detect() -> None:
    json.dump(detect.detect_all(), sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


def _do_companies_list() -> None:
    a_companies.list_cmd()


def _do_companies_add() -> None:
    a_companies.add_cmd()


def _do_add_repo() -> None:
    a_add_repo.run()


def _do_status() -> None:
    a_status.run()


def _do_ingest() -> None:
    a_ingest.run()


def _do_reports() -> None:
    a_reports.run(open_latest=True)


def _do_health() -> None:
    a_health.run()


def _do_backups_gc() -> None:
    res = backups.gc()
    print(
        f"deleted={len(res['deleted'])} freed={res['total_bytes_freed']} "
        f"dir={res['backup_dir']}"
    )


def _pick_company_repo() -> tuple[str | None, str | None]:
    """Interactively pick (company_slug, repo_name) from configured state files."""
    entries = state.list_all()
    if not entries:
        print("no configured (company, repo) pairs yet — run add-repo first")
        return None, None
    for i, e in enumerate(entries, 1):
        print(f"  {i}) {e['company']} / {e['repo']}  ({len(e.get('agents', []))} agents)")
    choice = (wizard.ask("Pick", "1") or "").strip()
    try:
        e = entries[int(choice) - 1]
    except (ValueError, IndexError):
        print(f"invalid choice: {choice!r}", file=sys.stderr)
        return None, None
    return e["company"], e["repo"]


def _do_scale() -> None:
    company, repo = _pick_company_repo()
    if not company:
        return
    delta_raw = (wizard.ask("Delta (e.g. +2 or -1)", "+1") or "").strip()
    try:
        delta = int(delta_raw)
    except ValueError:
        print(f"invalid delta: {delta_raw!r}", file=sys.stderr)
        return
    a_scale.run(company=company, repo=repo, delta=delta)


def _do_teardown() -> None:
    company, repo = _pick_company_repo()
    if not company:
        return
    if not wizard.ask_yes_no(f"Really teardown {company}/{repo}?", default=False):
        return
    a_teardown.run(company=company, repo=repo, yes=True)


def _do_verify() -> None:
    company, repo = _pick_company_repo()
    if not company:
        return
    a_verify.run(company=company, repo=repo)


def _do_relogin() -> None:
    company, repo = _pick_company_repo()
    if not company:
        return
    agent_raw = (wizard.ask("Agent id (blank = all)", "") or "").strip()
    agent_id = int(agent_raw) if agent_raw else None
    browser_pool.relogin(company=company, repo=repo, agent_id=agent_id)


def _do_install() -> None:
    """Menu entry: install opencode / re-run paperclip onboarding / report status."""
    sub = (wizard.ask(
        "install target [opencode/paperclip/check]", "check",
    ) or "").strip().lower()
    if sub == "opencode":
        _install_opencode_interactive()
        return
    if sub == "paperclip":
        if paperclip_install.is_running():
            print("[install] paperclip already responding on /api/health; skipping onboard")
        else:
            paperclip_install.install_via_npx()
            paperclip_install.wait_for_alive(timeout=120)
        return
    # default: check
    print(f"paperclip running: {paperclip_install.is_running()}")
    print(f"opencode installed: {opencode_install.is_installed()}")
    print(f"opencode version: {opencode_install.current_version()}")


def _do_memory() -> None:
    sub = (wizard.ask("memory subcommand [install/status/uninstall]", "status") or "").strip().lower()
    if sub == "install":
        a_memory.install()
    elif sub == "uninstall":
        a_memory.uninstall()
    else:
        a_memory.status()


# Menu registry: (choice, label, handler). Order is preserved in the rendered
# prompt and used for default lookup.
MENU: list[tuple[str, str, Callable[[], None]]] = [
    ("1", "detect            snapshot of host state", _do_detect),
    ("2", "companies list    show configured companies", _do_companies_list),
    ("3", "companies add     add a new company", _do_companies_add),
    ("4", "add-repo          attach a git repo to a company", _do_add_repo),
    ("5", "scale             +/- agents for a configured repo", _do_scale),
    ("6", "status            agent dashboard", _do_status),
    ("7", "verify            E2E verification plan / agent-browser run", _do_verify),
    ("8", "ingest            pull assigned Jira tickets", _do_ingest),
    ("9", "reports           list / open generated reports", _do_reports),
    ("10", "health           env URLs + scheduler + worktree fsck", _do_health),
    ("11", "relogin          open browser profile(s) for fresh login", _do_relogin),
    ("12", "teardown         remove a configured (company, repo)", _do_teardown),
    ("13", "memory           manage nobrainer-memory in this workspace", _do_memory),
    ("14", "backups-gc       sweep Paperclip backups now", _do_backups_gc),
    ("15", "install          opencode / paperclip / status check", _do_install),
]


def _menu() -> int:
    handlers = {key: fn for key, _label, fn in MENU}
    while True:
        print("\nnobrainer-paperclip-setup")
        for key, label, _fn in MENU:
            print(f"  {key}) {label}")
        print("  q) quit")
        choice = (wizard.ask("Choice", "1") or "").strip()
        if choice in ("q", "Q", "quit", "exit"):
            return 0
        handler = handlers.get(choice)
        if handler is None:
            print(f"unknown choice: {choice!r}", file=sys.stderr)
            continue
        handler()


def run() -> int:
    if not preferences.is_onboarded():
        rc = _onboard()
        if rc != 0:
            return rc
    return _menu()
