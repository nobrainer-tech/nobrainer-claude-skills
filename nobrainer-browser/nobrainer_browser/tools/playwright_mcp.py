"""Resolve a safe-version pin for ``@playwright/mcp`` and cache it.

The package itself is invoked on-demand via ``npx``; nothing is installed
globally here. We just look up the safe version (7-day cooldown by default)
and persist it under ``paths.state_file()`` so wire commands can use it.
"""

from __future__ import annotations

from typing import Any

from .. import npm_safe, paths

PACKAGE = "@playwright/mcp"


def install(*, cooldown_days: int = 7, dry_run: bool = False) -> dict[str, Any]:
    """Resolve and cache the safe version. No global install (uses npx)."""
    result: dict[str, Any] = {
        "tool": "playwright-mcp",
        "package": PACKAGE,
        "ok": False,
    }
    try:
        version = npm_safe.resolve_safe_version(PACKAGE, cooldown_days=cooldown_days)
    except npm_safe.NpmSafeError as exc:
        result["error"] = str(exc)
        return result

    result["safe_version"] = version
    result["spec"] = f"{PACKAGE}@{version}"

    if dry_run:
        result["dry_run"] = True
        result["ok"] = True
        return result

    # Cache the pin for the wire commands.
    state = paths.load_json(paths.state_file()) or {}
    if not isinstance(state, dict):
        state = {}
    state["playwright_mcp_version"] = version
    state["playwright_mcp_resolved_at"] = paths.now_utc_iso()
    paths.atomic_write_json(paths.state_file(), state)

    result["state_path"] = str(paths.state_file())
    result["ok"] = True
    return result
