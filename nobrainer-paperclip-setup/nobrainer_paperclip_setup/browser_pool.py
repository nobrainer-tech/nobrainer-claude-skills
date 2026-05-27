"""Allocate browser CDP ports and profile directories per agent."""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Optional

from . import browser, detect, paths, preferences, state as state_mod


def _profile_dir_for(company: str, repo: str, agent_id: int) -> Path:
    root = paths.browser_profiles_dir()
    # Slug company/repo to block Chromium flag-injection through path values
    # (a value like "--no-sandbox foo" would otherwise leak into argv). Coerce
    # agent_id to int explicitly so non-int values raise loudly.
    name = f"{paths._slug(company)}-{paths._slug(repo)}-agent-{int(agent_id)}"
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def allocate(company: str, repo: str, agent_id: int) -> tuple[int, Path]:
    """Pick the next free CDP port and provision the profile dir."""
    ports = detect.next_free_cdp_ports(1)
    return ports[0], _profile_dir_for(company, repo, agent_id)


def launch_for_agent(state: dict, agent_id: int) -> Optional[int]:
    """Open the configured browser for one agent. Returns the launched PID."""
    agent = next((a for a in state.get("agents", []) if a.get("id") == agent_id), None)
    if agent is None:
        return None

    browser_name = agent.get("browser") or preferences.get("browser_default", "chrome")
    binaries = browser.detect_available()
    binary = binaries.get(browser_name)
    if binary is None:
        print(
            f"[nobrainer-paperclip-setup] browser binary not found: {browser_name}",
            file=sys.stderr,
        )
        return None

    profile_path = Path(agent["browser_profile_path"])
    cdp_port = int(agent["cdp_port"])

    if browser.is_session_alive(cdp_port):
        return None

    proc = browser.launch(binary, profile_path, cdp_port, headed=True)
    for _ in range(40):
        if browser.is_session_alive(cdp_port):
            break
        time.sleep(0.25)
    return proc.pid


def relogin(repo: str, agent_id: Optional[int] = None, company: Optional[str] = None) -> int:
    """Open browser windows for one or all agents and wait for ENTER."""
    states: list[dict] = []
    if company is not None:
        s = state_mod.load(company, repo)
        if s:
            states.append(s)
    else:
        states = [s for s in state_mod.list_all() if s.get("repo") == repo]

    if not states:
        print(f"[nobrainer-paperclip-setup] no state for repo {repo!r}", file=sys.stderr)
        return 1

    for s in states:
        ids = [agent_id] if agent_id is not None else [a["id"] for a in s.get("agents", [])]
        for aid in ids:
            pid = launch_for_agent(s, aid)
            label = f"{s.get('company')}/{s.get('repo')} agent {aid}"
            if pid is None:
                print(f"  - {label}: already alive or browser missing")
            else:
                print(f"  - {label}: launched pid={pid}")

    print("Press ENTER after completing logins in all opened windows...")
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass
    return 0
