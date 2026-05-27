"""``health`` action: env URLs, scheduler list, worktree fsck, browser sessions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from .. import browser, paperclip_api, paths, state as state_mod, worktree
from ..detect import SCHEDULER_LABEL_PREFIX
from ..scheduler import current as current_scheduler


def _read_env_status(state: dict) -> dict:
    p = paths.state_file(state["company"], state["repo"]).with_suffix(".env_status.json")
    if not p.exists():
        return {"services": [], "note": "no status file (watcher may not have run yet)"}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"services": [], "note": "unreadable status file"}


def run(company: Optional[str] = None, repo: Optional[str] = None) -> int:
    sched_labels = current_scheduler().list_labels(prefix=SCHEDULER_LABEL_PREFIX)
    states = state_mod.list_all()
    if company:
        states = [s for s in states if s.get("company") == company]
    if repo:
        states = [s for s in states if s.get("repo") == repo]

    print(f"scheduler labels ({len(sched_labels)}):")
    for label in sched_labels:
        print(f"  - {label}")

    for s in states:
        api = paperclip_api.PaperclipAPI(
            url=s["paperclip"]["url"],
            token_env_key=s["paperclip"].get("token_env_key"),
        )
        print(f"\n{s['company']}/{s['repo']}")
        print(f"  paperclip: {'up' if api.health() else 'down'} ({s['paperclip']['url']})")
        env = _read_env_status(s)
        if env.get("services"):
            for svc in env["services"]:
                print(f"  env  {svc['name']:<12} {svc['url']:<50} {svc['status']}")
        else:
            print(f"  env  {env.get('note')}")
        for a in s.get("agents", []):
            wt = Path(a["worktree_path"])
            healthy = worktree.is_healthy(wt)
            alive = browser.is_session_alive(int(a.get("cdp_port") or 0))
            print(
                f"  agent {a['id']:>2}  worktree={'ok' if healthy else 'BROKEN':<7}  "
                f"browser={'alive' if alive else 'idle '}  cdp={a['cdp_port']}"
            )
    return 0
