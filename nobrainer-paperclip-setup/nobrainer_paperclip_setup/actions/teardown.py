"""``teardown`` action: remove worktrees, profiles, scheduler entries, agents."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

from .. import browser, companies, paperclip_api, paths, state as state_mod, wizard, worktree
from ..scheduler import current as current_scheduler


def run(company: str, repo: str, yes: bool = False) -> int:
    st = state_mod.load(company, repo)
    if not st:
        print(f"no state for {company}/{repo}", file=sys.stderr)
        return 1

    if not yes:
        confirmed = wizard.ask_yes_no(
            f"Tear down {company}/{repo} ({len(st.get('agents', []))} agents)?",
            default=False,
        )
        if not confirmed:
            print("aborted")
            return 1

    sched = current_scheduler()
    cmp = companies.get_company(company)
    api = paperclip_api.PaperclipAPI(
        url=st["paperclip"]["url"],
        token_env_key=st["paperclip"].get("token_env_key"),
    )

    for label in st.get("scheduler_labels", []):
        if label.endswith("backups-gc"):
            # global singleton — leave intact
            continue
        sched.remove(label)

    for a in st.get("agents", []):
        try:
            profile = Path(a.get("browser_profile_path", ""))
            if profile.exists():
                browser.kill_by_profile(profile)
                shutil.rmtree(profile, ignore_errors=True)
        except OSError as exc:
            print(f"warning: could not remove profile: {exc}", file=sys.stderr)
        try:
            worktree.remove(Path(a["worktree_path"]))
        except OSError as exc:
            print(f"warning: could not remove worktree: {exc}", file=sys.stderr)
        if cmp and cmp.get("paperclip_company_id") and a.get("paperclip_agent_id"):
            api.delete_agent(cmp["paperclip_company_id"], a["paperclip_agent_id"])

    state_mod.delete(company, repo)
    companies.remove_repo_from_company(company, repo)

    reports_root = paths.tickets_dir(company, repo)
    if wizard.ask_yes_no(f"Also delete generated reports under {reports_root}?", default=False):
        shutil.rmtree(reports_root, ignore_errors=True)

    print(f"tore down {company}/{repo}")
    return 0
