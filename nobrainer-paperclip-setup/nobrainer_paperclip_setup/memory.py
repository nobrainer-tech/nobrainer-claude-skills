"""Bootstrap the nobrainer-memory skill in the orchestrator workspace.

If the ``claude`` CLI is available we drive it directly; otherwise we print the
manual command and return a no-op success so the wizard can continue.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import paths, preferences


MEMORY_DIRNAME = "memory"


def detect_workspace() -> Path:
    pref = preferences.get("orchestrator_workspace")
    if pref:
        return Path(pref).expanduser()
    return Path(os.getcwd())


def is_memory_installed(workspace: Path | None = None) -> bool:
    ws = workspace or detect_workspace()
    candidates = [
        ws / MEMORY_DIRNAME,
        ws / ".claude" / "memory",
        ws / "CLAUDE.md",
    ]
    return any(c.exists() for c in candidates)


def install_memory(workspace: Path | None = None) -> int:
    ws = workspace or detect_workspace()
    ws.mkdir(parents=True, exist_ok=True)

    claude = shutil.which("claude")
    if claude is not None:
        rc = _run_claude(claude, ws)
    else:
        print(
            "[memory] claude CLI not found in PATH. To install manually:\n"
            "  1. cd " + str(ws) + "\n"
            "  2. claude --print '/nobrainer-memory install'",
            file=sys.stderr,
        )
        rc = 0  # not a failure of this skill

    preferences.update({
        "orchestrator_workspace": str(ws),
        "memory": {
            "installed": is_memory_installed(ws),
            "backend": "nobrainer-memory",
            "installed_at": paths.now_utc_iso(),
        },
    })
    return rc


def _run_claude(claude_bin: str, ws: Path) -> int:
    try:
        proc = subprocess.run(  # noqa: S603
            [claude_bin, "--print", "/nobrainer-memory install"],
            cwd=str(ws),
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        sys.stdout.write(proc.stdout or "")
        sys.stderr.write(proc.stderr or "")
        return proc.returncode
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        print(f"[memory] claude invocation failed: {exc}", file=sys.stderr)
        return 1


def status(workspace: Path | None = None) -> dict:
    ws = workspace or detect_workspace()
    return {
        "workspace": str(ws),
        "installed": is_memory_installed(ws),
        "preferences_snapshot": preferences.get("memory", {}),
    }


def uninstall_memory(workspace: Path | None = None) -> int:
    """We never delete user files; only clear the preferences flag."""
    preferences.update({
        "memory": {"installed": False, "backend": None, "installed_at": None},
    })
    return 0
