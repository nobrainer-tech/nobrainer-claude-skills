"""Install Microsoft Webwright into a skill-managed clone directory.

Pipeline:
  1. ``git clone https://github.com/microsoft/Webwright <data_dir>/webwright``
     (or ``git pull`` if already present).
  2. ``<python> -m pip install --user -e <clone_path>``.
  3. ``<python> -m playwright install chromium``.
  4. Print the plugin marketplace commands the user must run in Claude
     (slash commands cannot be issued from Python).
  5. Run ``codex plugin marketplace add <clone_path>`` if codex is on PATH;
     report rc.

Returns a structured result for the CLI surface. No personal data emitted.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Any

from .. import paths

REPO_URL = "https://github.com/microsoft/Webwright"
CLONE_DIRNAME = "webwright"
REQUIRED_ENV_KEYS = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENROUTER_API_KEY")


def _run_logged(args: list[str], action: str, *, timeout: int | None = None,
                cwd: str | None = None) -> tuple[int, str]:
    """Run ``args`` with stdout+stderr tee'd to a timestamped log."""
    log_file = paths.log_path(action)
    print(f"[webwright] {' '.join(args)}")
    print(f"[webwright] log: {log_file}")
    try:
        with log_file.open("w", encoding="utf-8") as fh:
            proc = subprocess.Popen(  # noqa: S603
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=cwd,
            )
            assert proc.stdout is not None
            try:
                for line in proc.stdout:
                    fh.write(line)
                    fh.flush()
                    sys.stdout.write(line)
                rc = proc.wait(timeout=timeout)
                return rc, str(log_file)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                return 124, str(log_file)
    except (FileNotFoundError, OSError) as exc:
        return 127, f"{log_file} (failed to launch: {exc})"


def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _check_api_keys() -> dict[str, bool]:
    return {k: bool(os.environ.get(k)) for k in REQUIRED_ENV_KEYS}


def install(*, cooldown_days: int = 7, dry_run: bool = False) -> dict[str, Any]:
    """Install Webwright into ``data_dir()/webwright``.

    ``cooldown_days`` is accepted for API symmetry but Webwright is pulled
    from GitHub, not npm, so the cooldown does not apply.
    """
    del cooldown_days  # not applicable to git/pip source

    result: dict[str, Any] = {
        "tool": "webwright",
        "clone_path": None,
        "steps": [],
        "env": _check_api_keys(),
        "next_steps_claude": [],
        "next_steps_codex": {},
        "ok": False,
    }

    if not any(result["env"].values()):
        print(
            "[webwright] WARNING: none of OPENAI_API_KEY, ANTHROPIC_API_KEY, "
            "OPENROUTER_API_KEY are set. Webwright requires one to operate.",
            file=sys.stderr,
        )

    if not _have("git"):
        result["error"] = "git not found in PATH"
        return result

    clone_path = paths.data_dir() / CLONE_DIRNAME
    result["clone_path"] = str(clone_path)

    if dry_run:
        result["dry_run"] = True
        result["ok"] = True
        return result

    # 1. Clone or update.
    if clone_path.exists() and (clone_path / ".git").exists():
        rc, log = _run_logged(["git", "-C", str(clone_path), "pull", "--ff-only"], "webwright-pull")
        result["steps"].append({"step": "git-pull", "rc": rc, "log": log})
        if rc != 0:
            return result
    else:
        if clone_path.exists():
            # Path exists but isn't a git checkout; bail rather than nuking user data.
            result["error"] = f"{clone_path} exists and is not a git checkout"
            return result
        rc, log = _run_logged(
            ["git", "clone", "--depth", "1", REPO_URL, str(clone_path)],
            "webwright-clone",
        )
        result["steps"].append({"step": "git-clone", "rc": rc, "log": log})
        if rc != 0:
            return result

    # 2. pip install -e --user.
    python = sys.executable
    rc, log = _run_logged(
        [python, "-m", "pip", "install", "--user", "-e", str(clone_path)],
        "webwright-pip-install",
    )
    result["steps"].append({"step": "pip-install", "rc": rc, "log": log})
    if rc != 0:
        return result

    # 3. Playwright chromium install.
    rc, log = _run_logged(
        [python, "-m", "playwright", "install", "chromium"],
        "webwright-playwright-install",
    )
    result["steps"].append({"step": "playwright-install-chromium", "rc": rc, "log": log})
    # Non-fatal; user can re-run.

    # 4. Claude plugin commands (we cannot execute slash commands; print them).
    result["next_steps_claude"] = [
        f"/plugin marketplace add {clone_path}",
        "/plugin install webwright@webwright",
    ]

    # 5. Codex plugin marketplace (shellable).
    if _have("codex"):
        rc, log = _run_logged(
            ["codex", "plugin", "marketplace", "add", str(clone_path)],
            "webwright-codex-marketplace",
        )
        result["next_steps_codex"] = {"rc": rc, "log": log,
                                      "note": "Restart Codex after this."}
    else:
        result["next_steps_codex"] = {"rc": 127, "note": "codex CLI not on PATH"}

    result["ok"] = True
    return result
