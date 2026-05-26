"""User-level preferences captured during onboarding.

Saved atomically to ``<config>/preferences.json``. Every action reads this so
the user is never asked the same thing twice. Companies and their repos live
inline; per-(company, repo) operational state lives separately in ``state.py``.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from . import paths

PREFS_FILENAME = "preferences.json"

DEFAULTS: dict[str, Any] = {
    "onboarded_at": None,
    "timezone": "UTC",
    "working_hours": {"start": "08:00", "end": "18:00"},
    "working_days": ["mon", "tue", "wed", "thu", "fri"],
    "max_concurrent_tickets": 4,
    "backend_default": "opencode-copilot",
    "browser_default": "chrome",
    "orchestrator_workspace": None,
    "memory": {"installed": False, "backend": None, "installed_at": None},
    "reports": {
        "format": "html",
        "open_in_browser": True,
        "retention_days": 30,
    },
    "routing_strategy": "round-robin",
    "companies": [],
}


def prefs_path() -> Path:
    return paths.config_dir() / PREFS_FILENAME


def load() -> dict[str, Any]:
    p = prefs_path()
    if not p.exists():
        return copy.deepcopy(DEFAULTS)
    try:
        loaded = json.loads(p.read_text(encoding="utf-8"))
    except OSError:
        return copy.deepcopy(DEFAULTS)
    except json.JSONDecodeError:
        paths.quarantine_broken(p)
        return copy.deepcopy(DEFAULTS)
    merged = copy.deepcopy(DEFAULTS)
    merged.update(loaded)
    return merged


def save(prefs: dict[str, Any]) -> None:
    paths.atomic_write_json(prefs_path(), prefs)


def is_onboarded() -> bool:
    return load().get("onboarded_at") is not None


def get(key: str, default: Any = None) -> Any:
    return load().get(key, default)


def set_value(key: str, value: Any) -> None:
    prefs = load()
    prefs[key] = value
    save(prefs)


def update(patch: dict[str, Any]) -> None:
    prefs = load()
    prefs.update(patch)
    save(prefs)
