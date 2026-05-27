"""Ingest assigned Jira tickets and dispatch them to agents as Paperclip tasks."""

from __future__ import annotations

import datetime as _dt
from typing import Any, Optional

from .. import (
    backend,
    companies,
    credentials,
    lock,
    paperclip_api,
    paths,
    preferences,
    state as state_mod,
)
from ..jira import get_client
from . import report as report_mod, routing, store


_DAY_ALIASES = {
    "mon": "mon", "monday": "mon",
    "tue": "tue", "tuesday": "tue",
    "wed": "wed", "wednesday": "wed",
    "thu": "thu", "thursday": "thu",
    "fri": "fri", "friday": "fri",
    "sat": "sat", "saturday": "sat",
    "sun": "sun", "sunday": "sun",
}


def _within_working_hours() -> bool:
    """True if now is inside the user's configured working window.

    Reads ``working_hours``, ``working_days``, ``timezone`` from preferences.
    Falls back to UTC and 24/7 if anything is malformed so a bad config never
    silently blocks all ingestion.
    """
    prefs = preferences.load()
    hours = prefs.get("working_hours") or {"start": "00:00", "end": "23:59"}
    days = prefs.get("working_days") or [
        "mon", "tue", "wed", "thu", "fri", "sat", "sun",
    ]
    tz_name = prefs.get("timezone") or "UTC"

    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(tz_name)
    except Exception:  # noqa: BLE001 — fallback for unknown TZ or stripped tzdata
        tz = _dt.timezone.utc

    now = _dt.datetime.now(tz=tz)
    today = now.strftime("%a").lower()
    norm_days = {_DAY_ALIASES.get(d.lower(), d.lower()[:3]) for d in days}
    if today not in norm_days:
        return False

    try:
        start_h, start_m = (int(x) for x in str(hours["start"]).split(":"))
        end_h, end_m = (int(x) for x in str(hours["end"]).split(":"))
    except (KeyError, ValueError, TypeError):
        return True  # malformed config — fail open

    now_min = now.hour * 60 + now.minute
    return start_h * 60 + start_m <= now_min <= end_h * 60 + end_m


def ingest_for_company(
    company_slug: str,
    *,
    force: bool = False,
) -> dict[str, Any]:
    if not force and not _within_working_hours():
        return {
            "company": company_slug,
            "ok": True,
            "reason": "outside working hours",
            "issues_seen": 0,
            "dispatched": [],
            "skipped": [],
            "ran_at": paths.now_utc_iso(),
        }

    company = companies.get_company(company_slug)
    if not company:
        return {"company": company_slug, "ok": False, "reason": "company not found"}

    client = get_client(company)
    if client is None:
        return {
            "company": company_slug,
            "ok": False,
            "reason": "jira disabled or backend missing",
        }

    jql = company.get("jira", {}).get("default_jql") or "assignee = currentUser()"
    try:
        issues = client.search_issues(jql)
    except Exception as exc:  # noqa: BLE001 — one company's jira hiccup must not crash the loop
        return {
            "company": company_slug,
            "ok": False,
            "reason": f"jira search failed: {type(exc).__name__}: {exc}",
            "ran_at": paths.now_utc_iso(),
        }

    dispatched: list[dict] = []
    skipped: list[dict] = []

    for repo in company.get("repos", []):
        st = state_mod.load(company_slug, repo)
        if not st:
            skipped.append({"repo": repo, "reason": "no state for repo"})
            continue
        if not st.get("agents"):
            skipped.append({"repo": repo, "reason": "no agents configured"})
            continue

        api = paperclip_api.PaperclipAPI(
            url=st.get("paperclip", {}).get("url", paperclip_api.DEFAULT_URL),
            token_env_key=st.get("paperclip", {}).get("token_env_key"),
        )

        for issue in issues:
            key = str(issue.get("key") or issue.get("id") or "")
            if not key:
                continue

            diff_status = store.diff(company_slug, repo, issue)
            sig = store.signature(issue)
            if diff_status == "unchanged" and store.was_dispatched(
                company_slug, repo, key, sig,
            ):
                # Snapshot matches AND we already dispatched this signature — skip.
                continue

            # Pick + state mutation must be atomic w.r.t. concurrent ticks so
            # two ingestion runs do not select the same agent index.
            with lock.exclusive("routing"):
                st = state_mod.load(company_slug, repo) or st
                try:
                    agent_id = routing.pick_agent(company_slug, repo, issue, st)
                except RuntimeError as exc:
                    skipped.append({"repo": repo, "key": key, "reason": str(exc)})
                    continue
                if agent_id is None:
                    skipped.append({
                        "repo": repo, "key": key,
                        "reason": "no healthy agents available",
                    })
                    continue
                # Persist the cursor bump immediately so a crash mid-ingest
                # does not redeliver the same agent.
                state_mod.save(company_slug, repo, st)

            agent = next(
                (a for a in st["agents"] if a.get("id") == agent_id), None,
            )
            if not agent or not agent.get("paperclip_agent_id"):
                skipped.append({
                    "repo": repo, "key": key,
                    "reason": "agent not registered with paperclip",
                })
                continue

            report_path = (
                paths.ticket_report_dir(company_slug, repo, key) / "report.html"
            )
            evidence = paths.evidence_dir(company_slug, repo, key)
            ticket_cache_path = store._ticket_file(company_slug, repo, key)

            prompt = backend.system_prompt(
                company=company_slug,
                repo=repo,
                agent_id=agent_id,
                ticket_path=ticket_cache_path,
                worktree_path=agent.get("worktree_path"),
                report_path=report_path,
            )

            payload = {
                "title": (issue.get("fields") or {}).get("summary", key),
                "prompt": prompt,
                "metadata": {
                    "ticket_key": key,
                    "company": company_slug,
                    "repo": repo,
                    "agent_id": agent_id,
                    "report_path": str(report_path),
                    "evidence_dir": str(evidence),
                    "queued_at": paths.now_utc_iso(),
                    "diff_state": diff_status,
                },
            }
            try:
                created = api.create_task_strict(agent["paperclip_agent_id"], payload)
            except paperclip_api.PaperclipAPIError as exc:
                # Do NOT save snapshot — retry on next tick. Cursor was already
                # bumped, which is fine: next retry simply picks the next agent.
                reason = f"paperclip create_task failed: {exc.kind}"
                if exc.status is not None:
                    reason += f" ({exc.status})"
                skipped.append({"repo": repo, "key": key, "reason": reason})
                continue

            # Order: dispatch -> snapshot -> dispatch log. Snapshot is the
            # source of truth for `diff`, dispatch log lets us retry across
            # snapshot writes that happened via other paths.
            store.save_snapshot(company_slug, repo, issue)
            store.mark_dispatched(company_slug, repo, key, sig)

            # write an initial placeholder report so the orchestrator can show progress
            report_mod.render(issue, {"status": "queued"}, evidence)

            dispatched.append({
                "repo": repo,
                "key": key,
                "agent_id": agent_id,
                "task_id": (created or {}).get("id"),
            })

    return {
        "company": company_slug,
        "ok": True,
        "issues_seen": len(issues),
        "dispatched": dispatched,
        "skipped": skipped,
        "ran_at": paths.now_utc_iso(),
    }


def ingest_all(*, force: bool = False) -> list[dict]:
    out: list[dict] = []
    for c in companies.list_companies():
        out.append(ingest_for_company(c["slug"], force=force))
    return out


def credentials_present(company_slug: str) -> Optional[str]:
    """Return missing env key name, or None if all required keys are set."""
    cmp = companies.get_company(company_slug)
    if not cmp:
        return None
    backend_name = (cmp.get("jira") or {}).get("backend")
    if backend_name == "rest-api":
        key = credentials.company_jira_pat_key(company_slug)
        if not credentials.get(key):
            return key
    return None
