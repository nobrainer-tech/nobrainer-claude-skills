"""Install and supervise the local Paperclip server.

Uses the upstream ``npx paperclipai onboard --yes`` flow for first install,
routed through :mod:`npm_safe` so the resolved version is always at least
7 days old (supply-chain cooldown). Registers a KeepAlive scheduler entry so
the server survives reboots and crashes.
"""

from __future__ import annotations

import shutil
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import npm_safe, paths
from .scheduler import current as current_scheduler
from .scheduler.base import ScheduleSpec

DEFAULT_URL = "http://localhost:3100"
SERVER_LABEL = "dev.nobrainer.paperclipsetup.paperclip-server"
PACKAGE = "paperclipai"


def is_running(url: str = DEFAULT_URL, timeout: float = 2.0) -> bool:
    try:
        with urllib.request.urlopen(f"{url}/api/health", timeout=timeout) as resp:  # noqa: S310
            return 200 <= resp.status < 500
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
        return False


def install_via_npx(extra_args: list[str] | None = None) -> int:
    """Run ``npx paperclipai@<safe-version> onboard --yes`` via :mod:`npm_safe`.

    The resolved version is the latest published >= 7 days ago. Returns the
    child exit code; ``127`` if the toolchain is missing.
    """
    args: list[str] = ["onboard", "--yes"]
    if extra_args:
        args.extend(extra_args)

    try:
        return npm_safe.run_npx(PACKAGE, args)
    except npm_safe.NpmSafeError as exc:
        print(
            "[paperclip-install] could not resolve a safe version of "
            f"{PACKAGE!r}: {exc}",
            file=sys.stderr,
        )
        print(
            "[paperclip-install] refusing to install. Re-run after the "
            "registry is reachable. Do NOT set NPM_SAFE_BYPASS=1 unless you "
            "fully trust today's release of the package.",
            file=sys.stderr,
        )
        return 127


def install_keepalive_scheduler(extra_args: list[str] | None = None) -> str:
    """Register the Paperclip server as a KeepAlive scheduler entry.

    The keep-alive command pins ``paperclipai@<safe-version>`` so a respawn
    after a registry-side compromise still uses the cooled-down build.
    """
    npx = shutil.which("npx") or "npx"
    try:
        version = npm_safe.resolve_safe_version(PACKAGE)
    except npm_safe.NpmSafeError as exc:
        print(
            f"[paperclip-install] WARNING: keep-alive will fall back to "
            f"unpinned {PACKAGE!r} because version resolution failed: {exc}",
            file=sys.stderr,
        )
        spec = PACKAGE
    else:
        spec = f"{PACKAGE}@{version}"

    cmd: list[str] = [npx, "-y", spec, "start"]
    if extra_args:
        cmd.extend(extra_args)

    log_dir = paths.logs_dir() / "paperclip-server"
    log_dir.mkdir(parents=True, exist_ok=True)
    schedule = ScheduleSpec(
        label=SERVER_LABEL,
        command=cmd,
        working_directory=Path.home(),
        keep_alive=True,
        stdout_log=log_dir / "stdout.log",
        stderr_log=log_dir / "stderr.log",
    )
    current_scheduler().install(schedule)
    return SERVER_LABEL


def wait_for_alive(url: str = DEFAULT_URL, timeout: float = 60.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if is_running(url):
            return True
        time.sleep(1.0)
    return False
