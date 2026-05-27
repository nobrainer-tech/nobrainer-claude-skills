"""``companies`` subcommands."""

from __future__ import annotations

import getpass
import json
import sys

from .. import companies as companies_mod, credentials, wizard


def list_cmd(json_out: bool = False) -> int:
    items = companies_mod.list_companies()
    if json_out:
        json.dump(items, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
        return 0
    if not items:
        print("(no companies configured)")
        return 0
    for c in items:
        jira = c.get("jira") or {}
        print(
            f"- {c.get('slug')}  ({c.get('display_name')})  "
            f"repos={len(c.get('repos', []))}  jira={jira.get('backend') if jira.get('enabled') else 'off'}"
        )
    return 0


def add_cmd() -> int:
    slug = wizard.ask("Company slug (lowercase, dashes)")
    if not slug:
        print("aborted: no slug given", file=sys.stderr)
        return 2
    name = wizard.ask("Display name", slug) or slug
    jira_enabled = wizard.ask_yes_no("Enable Jira ingestion?", default=True)
    jira_cfg: dict = {"enabled": False, "backend": "none"}
    if jira_enabled:
        backend = wizard.ask_choice(
            "Jira backend",
            ["atlassian-mcp", "rest-api", "none"],
            default="atlassian-mcp",
        ) or "atlassian-mcp"
        server_url = wizard.ask("Jira server URL", "https://example.atlassian.net")
        jql = wizard.ask(
            "Default JQL",
            "assignee = currentUser() AND statusCategory != Done",
        )
        poll = wizard.ask_int("Poll interval (minutes)", 1, 1440, 15)
        jira_cfg = {
            "enabled": True,
            "backend": backend,
            "server_url": server_url,
            "default_jql": jql,
            "poll_interval_minutes": poll,
            "ticket_types_handled": ["Bug", "Task", "Story"],
        }
        if backend == "rest-api":
            email = wizard.ask("Atlassian email for basic auth (optional)")
            if email:
                jira_cfg["email"] = email
            pat_key = credentials.company_jira_pat_key(slug)
            existing = credentials.get(pat_key)
            if not existing:
                try:
                    pat_value = getpass.getpass(
                        f"Paste Jira PAT (will be stored as {pat_key} in .env): "
                    ).strip() or None
                except (EOFError, KeyboardInterrupt):
                    pat_value = None
                if pat_value:
                    try:
                        credentials.put(pat_key, pat_value)
                    except RuntimeError as exc:
                        print(f"warning: could not save PAT yet: {exc}", file=sys.stderr)

    created = companies_mod.add_company(slug, name, jira=jira_cfg)
    print(f"company saved: {created['slug']}")
    return 0
