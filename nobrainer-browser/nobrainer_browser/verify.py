"""Health checks for the four tools.

Each check is best-effort and returns a dict with ``ok``, ``detail``, and
optional ``version``. No network calls except what the tools themselves do.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from typing import Any

from . import detect, paths


def _run(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    exe = shutil.which(cmd[0])
    if exe is None:
        return (127, "", f"{cmd[0]}: not found")
    try:
        proc = subprocess.run(  # noqa: S603
            [exe, *cmd[1:]],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return (proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip())
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return (1, "", str(exc))


def verify_webwright() -> dict[str, Any]:
    info = detect.detect_webwright()
    plugin = info.get("plugin_registered") or {}
    any_registered = any(plugin.values())
    from_source = info.get("installed_from_source", False)

    if not from_source and not any_registered:
        return {
            "ok": False,
            "detail": "webwright not installed (no source clone, no host registration)",
            "plugin_registered": plugin,
        }

    if from_source:
        rc, _out, _err = _run([
            sys.executable, "-c",
            "import importlib; importlib.import_module('webwright')",
        ])
        return {
            "ok": rc == 0 or any_registered,
            "detail": (
                "webwright importable" if rc == 0
                else ("module not importable but plugin registered" if any_registered
                      else "webwright module not importable")
            ),
            "path": info.get("path"),
            "playwright_chromium": info.get("playwright_chromium", False),
            "plugin_registered": plugin,
        }

    return {
        "ok": True,
        "detail": "webwright registered via marketplace (no local source)",
        "plugin_registered": plugin,
    }


def verify_playwright_mcp() -> dict[str, Any]:
    state = paths.load_json(paths.state_file()) or {}
    pin = state.get("playwright_mcp_version") if isinstance(state, dict) else None
    if not pin:
        return {"ok": False, "detail": "no cached safe-version pin; run install playwright-mcp"}
    # Best-effort: ``npx -y @playwright/mcp@<pin> --help`` is too heavy for a
    # health check (it downloads). Just report the pin.
    return {"ok": True, "detail": f"safe version cached: {pin}", "safe_version": pin}


def verify_playwright_cli() -> dict[str, Any]:
    rc, out, err = _run(["playwright", "--version"])
    if rc != 0:
        return {"ok": False, "detail": err or "playwright --version failed"}
    return {"ok": True, "detail": out, "version": out}


def verify_agent_browser() -> dict[str, Any]:
    rc, out, err = _run(["agent-browser", "--version"])
    if rc != 0:
        return {"ok": False, "detail": err or "agent-browser --version failed"}
    return {"ok": True, "detail": out, "version": out}


def verify_wiring() -> dict[str, Any]:
    return detect.detect_wiring()


def verify_all(tools: list[str] | None = None) -> dict[str, Any]:
    table = {
        "webwright": verify_webwright,
        "playwright-mcp": verify_playwright_mcp,
        "playwright-cli": verify_playwright_cli,
        "agent-browser": verify_agent_browser,
    }
    selected = tools or list(table.keys())
    out: dict[str, Any] = {"tools": {}, "wiring": verify_wiring()}
    for t in selected:
        check = table.get(t)
        if check is None:
            out["tools"][t] = {"ok": False, "detail": f"unknown tool: {t}"}
            continue
        out["tools"][t] = check()
    out["ok"] = all(v.get("ok") for v in out["tools"].values())
    return out
