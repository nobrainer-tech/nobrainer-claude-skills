"""``status`` action: per-company / per-repo dashboard."""

from __future__ import annotations

import json
import sys
import time
from typing import Optional

from .. import browser, paperclip_api, state as state_mod


def _snapshot(company: Optional[str], repo: Optional[str]) -> list[dict]:
    out: list[dict] = []
    for s in state_mod.list_all():
        if company and s.get("company") != company:
            continue
        if repo and s.get("repo") != repo:
            continue
        api = paperclip_api.PaperclipAPI(
            url=s.get("paperclip", {}).get("url", paperclip_api.DEFAULT_URL),
            token_env_key=s.get("paperclip", {}).get("token_env_key"),
        )
        paperclip_up = api.health()
        agents_view: list[dict] = []
        for a in s.get("agents", []):
            agents_view.append({
                "id": a.get("id"),
                "backend": a.get("backend"),
                "browser": a.get("browser"),
                "cdp_port": a.get("cdp_port"),
                "browser_alive": browser.is_session_alive(int(a.get("cdp_port") or 0)),
                "paperclip_agent_id": a.get("paperclip_agent_id"),
                "current_task_id": a.get("current_task_id"),
            })
        out.append({
            "company": s.get("company"),
            "repo": s.get("repo"),
            "repo_path": s.get("repo_path"),
            "paperclip": {"url": s["paperclip"]["url"], "up": paperclip_up},
            "agents": agents_view,
        })
    return out


def _render(snapshot: list[dict]) -> None:
    if not snapshot:
        print("(no configured repos)")
        return
    for entry in snapshot:
        pc = entry["paperclip"]
        print(f"\n{entry['company']}/{entry['repo']}  (paperclip: {pc['url']} -- {'up' if pc['up'] else 'down'})")
        print(f"  path: {entry['repo_path']}")
        for a in entry["agents"]:
            alive = "alive" if a["browser_alive"] else "idle"
            print(
                f"  - agent {a['id']:>2}  backend={a['backend']:<18}  "
                f"browser={a['browser']:<5} ({alive}) cdp={a['cdp_port']}  "
                f"task={a['current_task_id'] or '-'}"
            )


def run(
    repo: Optional[str] = None,
    company: Optional[str] = None,
    watch: bool = False,
    json_out: bool = False,
) -> int:
    if not watch:
        snap = _snapshot(company, repo)
        if json_out:
            json.dump(snap, sys.stdout, indent=2, default=str)
            sys.stdout.write("\n")
        else:
            _render(snap)
        return 0

    try:
        while True:
            snap = _snapshot(company, repo)
            sys.stdout.write("\033[2J\033[H")
            _render(snap)
            sys.stdout.flush()
            time.sleep(5.0)
    except KeyboardInterrupt:
        return 0
