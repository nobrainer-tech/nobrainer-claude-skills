"""Per-(company, repo) operational state.

One JSON file per ``(company_slug, repo_name)`` pair. Atomic writes only.
This is the single source of truth for agents, ports, browser profiles, and
scheduler labels owned by this skill.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from . import paths


def new_state(company: str, repo: str, repo_path: Path) -> dict[str, Any]:
    rp = Path(repo_path).resolve()
    if not rp.is_absolute() or not rp.is_dir() or not (rp / ".git").exists():
        raise ValueError(
            f"repo_path must be an absolute git repo dir, got {repo_path!r}"
        )
    now = paths.now_utc_iso()
    return {
        "company": company,
        "repo": repo,
        "repo_path": str(rp),
        "framework": "unknown",
        "paperclip": {"url": "http://localhost:3100", "token_env_key": None},
        "agents": [],
        "env_watchers": [],
        "scheduler_labels": [],
        "backups": {
            "retention_hours": 48,
            "min_keep": 1,
            "gc_interval_hours": 6,
            "scheduler_label": "dev.nobrainer.paperclipsetup.backups-gc",
        },
        "created_at": now,
        "updated_at": now,
    }


def load(company: str, repo: str) -> Optional[dict[str, Any]]:
    p = paths.state_file(company, repo)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except OSError:
        return None
    except json.JSONDecodeError:
        paths.quarantine_broken(p)
        return None


def save(company: str, repo: str, data: dict[str, Any]) -> Path:
    p = paths.state_file(company, repo)
    data["updated_at"] = paths.now_utc_iso()
    paths.atomic_write_json(p, data)
    return p


def delete(company: str, repo: str) -> bool:
    p = paths.state_file(company, repo)
    if p.exists():
        p.unlink()
        return True
    return False


def list_all() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in sorted(paths.state_dir().glob("*.json")):
        if f.name.startswith("_"):
            continue
        try:
            out.append(json.loads(f.read_text(encoding="utf-8")))
        except OSError:
            continue
        except json.JSONDecodeError:
            paths.quarantine_broken(f)
            continue
    return out


def list_for_company(company: str) -> list[dict[str, Any]]:
    return [s for s in list_all() if s.get("company") == company]


def next_agent_id(state: dict[str, Any]) -> int:
    ids = [a.get("id", 0) for a in state.get("agents", [])]
    return (max(ids) + 1) if ids else 1
