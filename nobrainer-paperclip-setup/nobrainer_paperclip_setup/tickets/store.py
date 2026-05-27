"""Local snapshot + dispatch cache for Jira tickets, keyed per (company, repo).

Layout::

    <data>/ticket-cache/<company>/<repo>/<KEY>.json        # per-ticket snapshot
    <data>/ticket-cache/<company>/<repo>/_dispatched.json  # dispatch log

The repo dimension matters: one company can have N repos (e.g. ``selenium`` and
``playwright``) and the same Jira ticket must be dispatched independently to
each. Keying only on ``(company, key)`` caused the second repo to silently
skip everything the first repo had already handled.

Atomic writes only. A legacy layout (``<company>/<KEY>.json`` without the repo
segment) is auto-migrated on first read: the file is copied into the requested
repo subdir, the legacy file is left in place so other repos can pick it up
the same way on their own first read. Once every active repo has migrated,
the legacy files are inert and can be removed manually.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Optional

from .. import paths


# Jira-style keys (``PROJ-123``) keep ``-`` intact; only path-unsafe chars
# collapse to ``_``. Preserves case so PROJ-123 and proj-123 don't collide.
_TICKET_KEY_RE = re.compile(r"[^A-Za-z0-9_-]+")


def _safe_key(key: str) -> str:
    return _TICKET_KEY_RE.sub("_", key).strip("_") or "TICKET"


def _repo_cache_dir(company: str, repo: str) -> Path:
    """Per-(company, repo) ticket cache directory. Always exists on return."""
    d = paths.ticket_cache_dir(company) / paths.slugify(repo)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _ticket_file(company: str, repo: str, key: str) -> Path:
    return _repo_cache_dir(company, repo) / f"{_safe_key(key)}.json"


def _legacy_ticket_file(company: str, key: str) -> Path:
    """Pre-repo-scoped path. Read-only — for one-shot migration only."""
    return paths.ticket_cache_dir(company) / f"{_safe_key(key)}.json"


def _migrate_legacy_if_present(company: str, repo: str, key: str) -> None:
    """If a legacy ``<company>/<KEY>.json`` exists but the per-repo file does
    not, copy it into the repo subdir. Best-effort; failures are silent.
    """
    new_path = _ticket_file(company, repo, key)
    if new_path.exists():
        return
    legacy = _legacy_ticket_file(company, key)
    if not legacy.is_file():
        return
    try:
        shutil.copy2(legacy, new_path)
    except OSError:
        # Leave the legacy file; subsequent reads will retry.
        pass


def save_snapshot(company: str, repo: str, ticket: dict) -> Path:
    key = ticket.get("key") or ticket.get("id") or "UNKNOWN"
    f = _ticket_file(company, repo, str(key))
    payload = dict(ticket)
    payload["_cached_at"] = paths.now_utc_iso()
    paths.atomic_write_json(f, payload, default=str)
    return f


def load_snapshot(company: str, repo: str, key: str) -> Optional[dict]:
    _migrate_legacy_if_present(company, repo, key)
    f = _ticket_file(company, repo, key)
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except OSError:
        return None
    except json.JSONDecodeError:
        paths.quarantine_broken(f)
        return None


def diff(company: str, repo: str, new_ticket: dict) -> str:
    """Return ``"new"``, ``"changed"``, or ``"unchanged"`` for (company, repo)."""
    key = str(new_ticket.get("key") or new_ticket.get("id") or "")
    cached = load_snapshot(company, repo, key)
    if cached is None:
        return "new"
    cached_signature = _signature(cached)
    new_signature = _signature(new_ticket)
    return "unchanged" if cached_signature == new_signature else "changed"


def signature(ticket: dict) -> str:
    """Public alias used to track last-dispatched signature."""
    return _signature(ticket)


def _signature(ticket: dict) -> str:
    fields = ticket.get("fields") or {}
    parts = [
        str(ticket.get("key", "")),
        str(fields.get("summary", "")),
        str(fields.get("status", {}).get("name", "")),
        str(fields.get("updated", "")),
    ]
    return "|".join(parts)


def _dispatch_log_path(company: str, repo: str) -> Path:
    return _repo_cache_dir(company, repo) / "_dispatched.json"


def _load_dispatch_log(company: str, repo: str) -> dict[str, str]:
    p = _dispatch_log_path(company, repo)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def was_dispatched(company: str, repo: str, key: str, sig: str) -> bool:
    return _load_dispatch_log(company, repo).get(key) == sig


def mark_dispatched(company: str, repo: str, key: str, sig: str) -> None:
    """Record that ``key`` with ``sig`` was successfully dispatched to ``repo``.

    Separate from snapshot to let transient API failures retry without losing
    the cached snapshot used for ``diff``. Keyed per repo so two repos under
    the same company don't suppress each other's dispatches.
    """
    log = _load_dispatch_log(company, repo)
    log[key] = sig
    paths.atomic_write_json(_dispatch_log_path(company, repo), log)


def list_recent(company: str, repo: str, since_iso: str) -> list[dict]:
    out: list[dict] = []
    root = _repo_cache_dir(company, repo)
    for f in root.glob("*.json"):
        if f.name.startswith("_"):
            continue
        try:
            payload = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if (payload.get("_cached_at") or "") >= since_iso:
            out.append(payload)
    return sorted(out, key=lambda p: p.get("_cached_at", ""), reverse=True)
