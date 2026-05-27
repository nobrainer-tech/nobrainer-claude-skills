"""``scale`` action — add or remove agents for a configured repo."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

from .. import (
    browser,
    companies,
    detect,
    lock,
    paperclip_api,
    preferences,
    provisioning,
    state as state_mod,
    worktree,
)


def run(company: str, repo: str, delta: int) -> int:
    if delta == 0:
        print("delta is zero; nothing to do")
        return 0

    cmp = companies.get_company(company)
    lock_name = f"state-{company}-{repo}"

    if delta > 0:
        if cmp is None:
            print(f"unknown company {company!r}", file=sys.stderr)
            return 1
        browser_name = preferences.get("browser_default", "chrome")
        backend_name = preferences.get("backend_default", "opencode-copilot")
        if browser.detect_available().get(browser_name) is None:
            print(f"browser {browser_name!r} not available", file=sys.stderr)
            return 1

        # All state mutation happens inside the per-(company, repo) lock so
        # two concurrent ``scale`` runs cannot overwrite each other's appended
        # agents. Port allocation uses its own global lock for the same reason
        # across unrelated repos.
        with lock.exclusive(lock_name):
            st = state_mod.load(company, repo)
            if not st:
                print(f"no state for {company}/{repo}", file=sys.stderr)
                return 1
            api = paperclip_api.PaperclipAPI(
                url=st["paperclip"]["url"],
                token_env_key=st["paperclip"].get("token_env_key"),
            )
            with lock.exclusive("port-alloc"):
                ports = detect.next_free_cdp_ports(delta)
            for i in range(delta):
                try:
                    agent = provisioning.provision_agent(
                        state=st,
                        company=cmp,
                        repo_name=repo,
                        repo_path=Path(st["repo_path"]),
                        cdp_port=ports[i],
                        browser_choice=browser_name,
                        backend_choice=backend_name,
                        api=api,
                    )
                except provisioning.AgentAlreadyProvisioned as exc:
                    print(f"{exc}; skipping")
                    continue
                st["agents"].append(agent)
                # persist incremental progress so partial failures don't lose state
                state_mod.save(company, repo, st)
            total = len(st["agents"])
        print(f"added {delta} agent(s); total now {total}")
        return 0

    # delta < 0 → remove agents. Same lock discipline.
    to_remove = abs(delta)
    with lock.exclusive(lock_name):
        st = state_mod.load(company, repo)
        if not st:
            print(f"no state for {company}/{repo}", file=sys.stderr)
            return 1
        api = paperclip_api.PaperclipAPI(
            url=st["paperclip"]["url"],
            token_env_key=st["paperclip"].get("token_env_key"),
        )
        if to_remove >= len(st["agents"]):
            print(
                f"refusing to remove {to_remove} of {len(st['agents'])} agents; "
                "use `teardown` to remove the whole repo",
                file=sys.stderr,
            )
            return 1
        victims = st["agents"][-to_remove:]
        for agent in victims:
            if cmp and cmp.get("paperclip_company_id") and agent.get("paperclip_agent_id"):
                api.delete_agent(cmp["paperclip_company_id"], agent["paperclip_agent_id"])
            worktree.remove(Path(agent["worktree_path"]))
            # Mirror teardown: kill browser bound to profile, then rmtree the dir.
            profile = agent.get("browser_profile_path")
            if profile:
                profile_path = Path(profile)
                try:
                    browser.kill_by_profile(profile_path)
                except Exception as exc:  # noqa: BLE001
                    print(f"warning: kill_by_profile failed: {exc}", file=sys.stderr)
                shutil.rmtree(profile_path, ignore_errors=True)
        st["agents"] = st["agents"][:-to_remove]
        state_mod.save(company, repo, st)
        total = len(st["agents"])
    print(f"removed {to_remove} agent(s); total now {total}")
    return 0
