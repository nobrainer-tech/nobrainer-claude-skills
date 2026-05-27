"""``add-repo``: attach a git repo to a company, allocate agents end-to-end."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from .. import (
    backend,
    backups,
    browser,
    browser_pool,
    companies,
    credentials,
    detect,
    lock,
    paperclip_api,
    paths,
    preferences,
    provisioning,
    state as state_mod,
    wizard,
)
from ..scheduler import current as current_scheduler
from ..scheduler.base import ScheduleSpec


def _pick_company(default_slug: Optional[str]) -> Optional[dict]:
    items = companies.list_companies()
    if not items:
        print("no companies configured; run `companies add` first", file=sys.stderr)
        return None
    if default_slug:
        c = companies.get_company(default_slug)
        if c:
            return c
    slugs = [c["slug"] for c in items]
    pick = wizard.ask_choice("Pick a company", slugs, default=slugs[0])
    return companies.get_company(pick) if pick else None


def _install_env_watcher(state: dict) -> Optional[str]:
    sched = current_scheduler()
    watcher = paths.templates_dir() / "env_watcher.py"
    if not watcher.exists():
        return None
    state_file = paths.state_file(state["company"], state["repo"])
    label = f"dev.nobrainer.paperclipsetup.{state['company']}.{state['repo']}.env-watcher"
    try:
        if sched.is_installed(label):
            return label
    except Exception as exc:  # noqa: BLE001
        print(f"warning: could not query scheduler: {exc}", file=sys.stderr)
        # Fall through and try to install anyway
    spec = ScheduleSpec(
        label=label,
        command=[sys.executable, str(watcher), str(state_file)],
        working_directory=Path.home(),
        interval_seconds=120,
    )
    try:
        sched.install(spec)
    except Exception as exc:  # noqa: BLE001 — scheduler failures must not abort add-repo
        print(f"warning: could not install env-watcher: {exc}", file=sys.stderr)
        return None
    return label


def _install_backups_gc() -> Optional[str]:
    sched = current_scheduler()
    label = "dev.nobrainer.paperclipsetup.backups-gc"
    try:
        if sched.is_installed(label):
            return label
    except Exception as exc:  # noqa: BLE001
        print(f"warning: could not list scheduler labels: {exc}", file=sys.stderr)
        return None
    spec = ScheduleSpec(
        label=label,
        command=[sys.executable, "-m", "nobrainer_paperclip_setup", "backups-gc"],
        working_directory=Path.home(),
        interval_seconds=6 * 3600,
    )
    try:
        sched.install(spec)
    except Exception as exc:  # noqa: BLE001
        print(f"warning: could not install backups-gc: {exc}", file=sys.stderr)
        return None
    return label


def run(
    repo_path: Optional[str] = None,
    company_slug: Optional[str] = None,
    non_interactive: bool = False,
) -> int:
    company = _pick_company(company_slug)
    if not company:
        return 2

    path = Path(repo_path).expanduser().resolve() if repo_path else None
    if path is None:
        picked = wizard.ask_path("Absolute path to git repo", must_exist=True, default=Path.cwd())
        if picked is None:
            print("aborted: no repo path", file=sys.stderr)
            return 2
        path = picked.resolve()
    if not (path / ".git").exists():
        print(f"not a git repo: {path}", file=sys.stderr)
        return 2

    repo_name = path.name
    companies.add_repo_to_company(company["slug"], repo_name)

    # Pre-lock peek for prompt defaults only. Never mutated, never saved —
    # the canonical load + mutate + save happens inside the lock below so two
    # concurrent invocations can't clobber each other's appended agents.
    peek = state_mod.load(company["slug"], repo_name)
    peek_count = len(peek.get("agents", [])) if peek else 0

    desired_total = wizard.ask_int(
        f"How many agents for {repo_name}?",
        min_value=1, max_value=20,
        default=max(1, peek_count or 2),
    )

    browser_choice = wizard.ask_choice(
        "Browser to use for new agents",
        ["chrome", "edge", "brave"],
        default=preferences.get("browser_default", "chrome"),
    ) or "chrome"
    backend_choice = wizard.ask_choice(
        "Backend to use",
        list(backend.SUPPORTED_BACKENDS),
        default=preferences.get("backend_default", "opencode-copilot"),
    ) or "opencode-copilot"

    available = browser.detect_available()
    if available.get(browser_choice) is None:
        print(f"browser {browser_choice!r} not found on this host", file=sys.stderr)
        return 1

    # Per-(company, repo) lock so unrelated repos do not serialize, but two
    # ``add-repo``/``scale`` runs for the SAME repo do. State load + mutate +
    # save all happen inside the same lock — otherwise a stale in-memory copy
    # overwrites a concurrent run's appended agent.
    lock_name = f"state-{company['slug']}-{repo_name}"
    state: dict
    with lock.exclusive(lock_name):
        existing = state_mod.load(company["slug"], repo_name)
        state = existing or state_mod.new_state(
            company["slug"], repo_name, path,
        )
        state["paperclip"]["token_env_key"] = credentials.company_token_key(
            company["slug"],
        )

        current_count = len(state.get("agents", []))
        delta = desired_total - current_count
        if delta <= 0:
            print(f"already at {current_count} agents; nothing to add")
            if existing is None:
                state_mod.save(company["slug"], repo_name, state)
            return 0

        api = paperclip_api.PaperclipAPI(
            url=state["paperclip"]["url"],
            token_env_key=state["paperclip"]["token_env_key"],
        )

        # Separate port-alloc lock so unrelated repos can still serialize on
        # port allocation without blocking on this repo's state mutations.
        with lock.exclusive("port-alloc"):
            ports = detect.next_free_cdp_ports(delta)

        for i in range(delta):
            try:
                agent = provisioning.provision_agent(
                    state=state,
                    company=company,
                    repo_name=repo_name,
                    repo_path=path,
                    cdp_port=ports[i],
                    browser_choice=browser_choice,
                    backend_choice=backend_choice,
                    api=api,
                )
            except provisioning.AgentAlreadyProvisioned as exc:
                print(f"{exc}; skipping")
                continue
            state["agents"].append(agent)
            # Persist after EACH agent so partial failures keep partial progress.
            state_mod.save(company["slug"], repo_name, state)

        # Scheduler label installation must also happen inside the lock — it
        # mutates ``state["scheduler_labels"]`` and saves again.
        env_label = _install_env_watcher(state)
        if env_label and env_label not in state["scheduler_labels"]:
            state["scheduler_labels"].append(env_label)

        backups_label = _install_backups_gc()
        if backups_label and backups_label not in state["scheduler_labels"]:
            state["scheduler_labels"].append(backups_label)

        state_mod.save(company["slug"], repo_name, state)

    # Best-effort opening of browsers for fresh login. Skip entirely in
    # non-interactive mode so automated --yes runs never block on stdin.
    if not non_interactive and wizard.ask_yes_no(
        "Launch browsers now for first-time login?", default=True,
    ):
        for agent in state["agents"][-delta:]:
            browser_pool.launch_for_agent(state, agent["id"])
        print("Press ENTER after completing logins in all opened windows...")
        try:
            input()
        except (EOFError, KeyboardInterrupt):
            pass

    # Garbage-collect orphan backups one time as a sanity check
    backups.gc(retention_hours=48, min_keep=1, dry_run=True)
    return 0
