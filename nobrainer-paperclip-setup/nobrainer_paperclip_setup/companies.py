"""Company CRUD layered on top of preferences.json.

A "company" matches Paperclip's native term: a top-level tenant that owns
agents, repos, and credentials. Slugs are lowercased and used as filename and
env-var prefixes.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from . import preferences


# Lowercase-only, ``-`` as the sole separator. Underscores collapse to ``-``
# (matches the historical state-filename naming so we never invalidate
# existing on-disk state for companies with underscores in their slug).
_SLUG_RE = re.compile(r"[^a-z0-9-]+")


def _slug(value: str) -> str:
    s = _SLUG_RE.sub("-", value.lower()).strip("-")
    return s or "default"


def _company_template(slug: str, display_name: str, **kwargs: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "slug": slug,
        "display_name": display_name,
        "paperclip_company_id": None,
        "jira": {
            "enabled": False,
            "backend": "none",
            "server_url": None,
            "default_jql": "assignee = currentUser() AND statusCategory != Done",
            "poll_interval_minutes": 15,
            "ticket_types_handled": ["Bug", "Task", "Story"],
        },
        "repos": [],
    }
    if "jira" in kwargs and isinstance(kwargs["jira"], dict):
        base["jira"].update(kwargs.pop("jira"))
    base.update(kwargs)
    return base


def list_companies() -> list[dict[str, Any]]:
    return list(preferences.load().get("companies", []))


def get_company(slug: str) -> Optional[dict[str, Any]]:
    slug_norm = _slug(slug)
    for c in list_companies():
        if c.get("slug") == slug_norm:
            return c
    return None


def add_company(slug: str, display_name: str, **kwargs: Any) -> dict[str, Any]:
    slug_norm = _slug(slug)
    prefs = preferences.load()
    companies = list(prefs.get("companies", []))
    for c in companies:
        if c.get("slug") == slug_norm:
            return c
    company = _company_template(slug_norm, display_name, **kwargs)
    companies.append(company)
    prefs["companies"] = companies
    preferences.save(prefs)
    return company


def update_company(slug: str, patch: dict[str, Any]) -> Optional[dict[str, Any]]:
    slug_norm = _slug(slug)
    prefs = preferences.load()
    companies = list(prefs.get("companies", []))
    updated: Optional[dict[str, Any]] = None
    for c in companies:
        if c.get("slug") == slug_norm:
            for k, v in patch.items():
                if k == "jira" and isinstance(v, dict) and isinstance(c.get("jira"), dict):
                    c["jira"].update(v)
                else:
                    c[k] = v
            updated = c
            break
    if updated is not None:
        prefs["companies"] = companies
        preferences.save(prefs)
    return updated


def add_repo_to_company(slug: str, repo_name: str) -> bool:
    slug_norm = _slug(slug)
    prefs = preferences.load()
    for c in prefs.get("companies", []):
        if c.get("slug") == slug_norm:
            repos = list(c.get("repos", []))
            if repo_name in repos:
                return False
            repos.append(repo_name)
            c["repos"] = repos
            preferences.save(prefs)
            return True
    return False


def remove_repo_from_company(slug: str, repo_name: str) -> bool:
    slug_norm = _slug(slug)
    prefs = preferences.load()
    for c in prefs.get("companies", []):
        if c.get("slug") == slug_norm:
            repos = [r for r in c.get("repos", []) if r != repo_name]
            if len(repos) == len(c.get("repos", [])):
                return False
            c["repos"] = repos
            preferences.save(prefs)
            return True
    return False


def remove_company(slug: str) -> bool:
    slug_norm = _slug(slug)
    prefs = preferences.load()
    before = prefs.get("companies", [])
    after = [c for c in before if c.get("slug") != slug_norm]
    if len(after) == len(before):
        return False
    prefs["companies"] = after
    preferences.save(prefs)
    return True


def slug_of(value: str) -> str:
    return _slug(value)
