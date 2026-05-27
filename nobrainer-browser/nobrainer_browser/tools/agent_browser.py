"""Install Vercel Labs' ``agent-browser`` CLI.

Default install path is npm (works on macOS/Windows/Linux without extra
toolchains). Users may opt into ``cargo`` (Rust toolchain required) or
``brew`` (macOS/Linux only) via ``method=``.

Post-install:
  1. ``agent-browser install`` to fetch Chrome for Testing.
  2. ``npx skills add vercel-labs/agent-browser`` to register the discovery
     stub used by Vercel's Skills system.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from typing import Any

from .. import npm_safe, paths

PACKAGE = "agent-browser"
SKILLS_REF = "vercel-labs/agent-browser"

VALID_METHODS = ("npm", "cargo", "brew")


def _run_logged(args: list[str], action: str, *, timeout: int | None = None) -> tuple[int, str]:
    log_file = paths.log_path(action)
    print(f"[agent-browser] {' '.join(args)}")
    print(f"[agent-browser] log: {log_file}")
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


def _install_npm(cooldown_days: int, dry_run: bool) -> dict[str, Any]:
    return npm_safe.install_global(PACKAGE, cooldown_days=cooldown_days, dry_run=dry_run)


def _install_cargo(dry_run: bool) -> dict[str, Any]:
    cargo = shutil.which("cargo")
    if cargo is None:
        return {"rc": 127, "error": "cargo not found in PATH"}
    args = [cargo, "install", PACKAGE]
    if dry_run:
        return {"rc": 0, "dry_run": True, "args": args}
    rc, log = _run_logged(args, "agent-browser-cargo-install", timeout=None)
    return {"rc": rc, "log_path": log}


def _install_brew(dry_run: bool) -> dict[str, Any]:
    brew = shutil.which("brew")
    if brew is None:
        return {"rc": 127, "error": "brew not found in PATH"}
    args = [brew, "install", PACKAGE]
    if dry_run:
        return {"rc": 0, "dry_run": True, "args": args}
    rc, log = _run_logged(args, "agent-browser-brew-install")
    return {"rc": rc, "log_path": log}


def install(
    *,
    cooldown_days: int = 7,
    dry_run: bool = False,
    method: str = "npm",
    with_deps: bool = False,
) -> dict[str, Any]:
    if method not in VALID_METHODS:
        return {"tool": "agent-browser", "ok": False, "error": f"invalid method: {method}"}

    result: dict[str, Any] = {"tool": "agent-browser", "method": method, "ok": False}

    if method == "npm":
        try:
            install_info = _install_npm(cooldown_days=cooldown_days, dry_run=dry_run)
        except npm_safe.NpmSafeError as exc:
            result["error"] = str(exc)
            return result
        result["install"] = install_info
        if install_info.get("rc", 1) != 0:
            return result
    elif method == "cargo":
        info = _install_cargo(dry_run=dry_run)
        result["install"] = info
        if info.get("rc", 1) != 0:
            return result
    elif method == "brew":
        info = _install_brew(dry_run=dry_run)
        result["install"] = info
        if info.get("rc", 1) != 0:
            return result

    if dry_run:
        result["ok"] = True
        return result

    # Post-install 1: download Chrome for Testing.
    binary = shutil.which("agent-browser")
    if binary is None:
        result["error"] = "agent-browser installed but binary not on PATH"
        return result
    post_args = [binary, "install"]
    if with_deps and sys.platform.startswith("linux"):
        post_args.append("--with-deps")
    rc, log = _run_logged(post_args, "agent-browser-post-install")
    result["chrome_for_testing"] = {"rc": rc, "log": log}
    if rc != 0:
        return result

    # Post-install 2: Vercel skills discovery stub.
    npx = shutil.which("npx")
    if npx is None:
        result["skills_stub"] = {"rc": 127, "error": "npx not on PATH"}
    else:
        rc, log = _run_logged([npx, "-y", "skills", "add", SKILLS_REF],
                              "agent-browser-skills-add")
        result["skills_stub"] = {"rc": rc, "log": log,
                                 "note": "Discovery stub registered with Vercel skills."}

    result["ok"] = True
    return result
