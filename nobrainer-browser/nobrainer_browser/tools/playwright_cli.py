"""Install the global Playwright test-framework CLI.

Pipeline:
  1. ``npm install -g playwright@<safe-version>`` via ``npm_safe.install_global``.
  2. ``npx playwright install`` (downloads Chromium/Firefox/WebKit drivers).
     On Linux, ``--with-deps`` is appended when ``with_deps=True``.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from typing import Any

from .. import npm_safe, paths

PACKAGE = "playwright"


def _run_logged(args: list[str], action: str, *, timeout: int | None = None) -> tuple[int, str]:
    log_file = paths.log_path(action)
    print(f"[playwright-cli] {' '.join(args)}")
    print(f"[playwright-cli] log: {log_file}")
    try:
        with log_file.open("w", encoding="utf-8") as fh:
            proc = subprocess.Popen(  # noqa: S603
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            assert proc.stdout is not None
            try:
                for line in proc.stdout:
                    fh.write(line)
                    fh.flush()
                    sys.stdout.write(line)
                return proc.wait(timeout=timeout), str(log_file)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                return 124, str(log_file)
    except (FileNotFoundError, OSError) as exc:
        return 127, f"{log_file} (failed to launch: {exc})"


def install(
    *,
    cooldown_days: int = 7,
    dry_run: bool = False,
    with_deps: bool = False,
) -> dict[str, Any]:
    result: dict[str, Any] = {"tool": "playwright-cli", "package": PACKAGE, "ok": False}
    try:
        install_info = npm_safe.install_global(
            PACKAGE,
            cooldown_days=cooldown_days,
            dry_run=dry_run,
        )
    except npm_safe.NpmSafeError as exc:
        result["error"] = str(exc)
        return result

    result["install"] = install_info
    if install_info.get("rc", 1) != 0:
        return result

    if dry_run:
        result["ok"] = True
        return result

    # Post-install: download browser drivers via the newly installed CLI.
    pw = shutil.which("playwright")
    if pw is None:
        # Fallback to npx with the pinned version.
        version = install_info.get("version", "latest")
        npx = shutil.which("npx")
        if npx is None:
            result["error"] = "playwright installed but neither playwright nor npx on PATH"
            return result
        argv = [npx, "-y", f"{PACKAGE}@{version}", "install"]
    else:
        argv = [pw, "install"]
    if with_deps and sys.platform.startswith("linux"):
        argv.append("--with-deps")
    rc, log = _run_logged(argv, "playwright-cli-browsers-install")
    result["browsers_install"] = {"rc": rc, "log": log}
    result["ok"] = rc == 0
    return result
