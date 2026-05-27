"""Wire the Playwright MCP server into Claude Code.

Strategy:
  1. Try ``claude mcp add playwright npx "@playwright/mcp@<safe_version>"``.
  2. If the CLI is missing or returns non-zero, fall back to editing
     ``~/.claude.json`` (or a caller-supplied path) atomically.

Both paths leave a structured result dict for the CLI surface.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from .. import paths

SERVER_NAME = "playwright"
NPM_PACKAGE = "@playwright/mcp"


def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
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


def _spec(safe_version: str) -> str:
    return f"{NPM_PACKAGE}@{safe_version}"


def wire_playwright_mcp(
    safe_version: str,
    *,
    config_path: Path | None = None,
    force_fallback: bool = False,
) -> dict[str, Any]:
    """Register the Playwright MCP server with Claude.

    Args:
        safe_version: Version string (or ``"latest"``) that npm_safe resolved.
        config_path: Override ``~/.claude.json``; used by tests.
        force_fallback: Skip the CLI attempt (used by tests and ``--method=json``).

    Returns: ``{"method": "cli"|"settings.json", "rc": int, "path": str|None,
    "spec": str, "server": str}``.
    """
    spec = _spec(safe_version)

    if not force_fallback and shutil.which("claude") is not None:
        rc, out, err = _run(["claude", "mcp", "add", SERVER_NAME, "npx", spec])
        if rc == 0:
            return {
                "method": "cli",
                "rc": 0,
                "path": None,
                "spec": spec,
                "server": SERVER_NAME,
                "stdout": out,
            }
        # Fall through to JSON edit; record CLI failure for the caller.
        cli_error = err or out or f"rc={rc}"
    else:
        cli_error = None if force_fallback else "claude CLI not found"

    path = config_path if config_path is not None else paths.claude_settings_file()
    data = paths.load_json(path) or {}
    if not isinstance(data, dict):
        data = {}
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        servers = {}
        data["mcpServers"] = servers
    servers[SERVER_NAME] = {
        "command": "npx",
        "args": [spec],
    }
    paths.atomic_write_json(path, data)
    return {
        "method": "settings.json",
        "rc": 0,
        "path": str(path),
        "spec": spec,
        "server": SERVER_NAME,
        "cli_error": cli_error,
    }


def unwire_playwright_mcp(
    *,
    config_path: Path | None = None,
) -> dict[str, Any]:
    """Remove the Playwright MCP server from Claude. CLI first, then JSON."""
    removed_cli = False
    if shutil.which("claude") is not None:
        rc, _out, _err = _run(["claude", "mcp", "remove", SERVER_NAME])
        removed_cli = rc == 0

    path = config_path if config_path is not None else paths.claude_settings_file()
    removed_json = False
    if path.exists():
        data = paths.load_json(path) or {}
        if isinstance(data, dict):
            servers = data.get("mcpServers")
            if isinstance(servers, dict) and SERVER_NAME in servers:
                servers.pop(SERVER_NAME, None)
                paths.atomic_write_json(path, data)
                removed_json = True

    return {
        "method": "cli" if removed_cli else ("settings.json" if removed_json else "none"),
        "removed_cli": removed_cli,
        "removed_json": removed_json,
        "path": str(path),
        "server": SERVER_NAME,
    }
