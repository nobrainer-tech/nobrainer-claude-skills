"""Install Microsoft Webwright and register it with one or more hosts.

Two install modes:

  * ``marketplace`` (default, recommended): no local clone, no pip install, no
    Playwright download. The host's plugin loader fetches Webwright from
    ``microsoft/Webwright`` on GitHub when the user runs the marketplace
    commands. Slash commands cannot be issued from Python; for Claude we
    return the commands the user must paste. For Codex we shell out to
    ``codex plugin marketplace add microsoft/Webwright``.

  * ``source`` (opt-in): clone ``microsoft/Webwright`` into
    ``<data_dir>/webwright``, run ``pip install --user -e <clone>`` and
    ``python -m playwright install chromium``. Hosts are then registered
    against the LOCAL absolute path. ``openclaw`` and ``hermes`` require
    this mode because they only accept a local checkout.

Supported hosts: ``claude``, ``codex``, ``openclaw``, ``hermes``. The
``uninstall`` companion removes the registration (and optionally the clone).

No personal data; cross-platform (macOS/Windows/Linux); stdlib only.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from .. import paths

REPO_URL = "https://github.com/microsoft/Webwright"
REPO_SPEC = "microsoft/Webwright"  # GitHub owner/repo for marketplace mode
PLUGIN_ID = "webwright@webwright"
CLONE_DIRNAME = "webwright"
REQUIRED_ENV_KEYS = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENROUTER_API_KEY")

VALID_MODES = ("marketplace", "source")
VALID_HOSTS = ("claude", "codex", "openclaw", "hermes")
DEFAULT_HOSTS = ("claude", "codex")
SOURCE_ONLY_HOSTS = ("openclaw", "hermes")


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


def _normalize_hosts(hosts: list[str] | None) -> tuple[list[str], list[str]]:
    """Return (valid_hosts, invalid_hosts) preserving caller order, deduped."""
    if hosts is None:
        return list(DEFAULT_HOSTS), []
    seen: set[str] = set()
    valid: list[str] = []
    invalid: list[str] = []
    for h in hosts:
        key = h.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        if key in VALID_HOSTS:
            valid.append(key)
        else:
            invalid.append(key)
    return valid, invalid


def _hermes_skill_link() -> Path:
    return Path.home() / ".hermes" / "skills" / "webwright"


# ---------------------------------------------------------------------------
# Host registration helpers (marketplace mode)
# ---------------------------------------------------------------------------


def _register_claude_marketplace() -> dict[str, Any]:
    return {
        "method": "slash-commands",
        "next_steps": [
            f"/plugin marketplace add {REPO_SPEC}",
            f"/plugin install {PLUGIN_ID}",
        ],
        "note": "Slash commands cannot be issued from Python. Paste them in Claude Code.",
    }


def _register_codex_marketplace(*, dry_run: bool) -> dict[str, Any]:
    cmd = ["codex", "plugin", "marketplace", "add", REPO_SPEC]
    if dry_run:
        return {"method": "cli", "dry_run": True, "command": cmd}
    if not _have("codex"):
        return {"method": "cli", "rc": 127, "error": "codex CLI not on PATH",
                "next_steps": [" ".join(cmd), "codex", "/plugins"]}
    rc, log = _run_logged(cmd, "webwright-codex-marketplace")
    return {"method": "cli", "rc": rc, "log": log,
            "note": "After this completes, run `codex` and then `/plugins` to confirm."}


def _reject_source_only_host(host: str) -> dict[str, Any]:
    return {
        "method": "n/a",
        "error": (
            f"{host} requires --mode source: it installs from a local path, "
            "not from a GitHub marketplace spec. Re-run with --mode source."
        ),
    }


# ---------------------------------------------------------------------------
# Host registration helpers (source mode)
# ---------------------------------------------------------------------------


def _register_claude_source(clone_path: Path) -> dict[str, Any]:
    return {
        "method": "slash-commands",
        "next_steps": [
            f"/plugin marketplace add {clone_path}",
            f"/plugin install {PLUGIN_ID}",
        ],
        "note": "Slash commands cannot be issued from Python. Paste them in Claude Code.",
    }


def _register_codex_source(clone_path: Path, *, dry_run: bool) -> dict[str, Any]:
    cmd = ["codex", "plugin", "marketplace", "add", str(clone_path)]
    if dry_run:
        return {"method": "cli", "dry_run": True, "command": cmd}
    if not _have("codex"):
        return {"method": "cli", "rc": 127, "error": "codex CLI not on PATH",
                "next_steps": [" ".join(cmd)]}
    rc, log = _run_logged(cmd, "webwright-codex-marketplace")
    return {"method": "cli", "rc": rc, "log": log}


def _register_openclaw_source(clone_path: Path, *, dry_run: bool) -> dict[str, Any]:
    install_cmd = ["openclaw", "plugins", "install", str(clone_path)]
    restart_cmd = ["openclaw", "gateway", "restart"]
    if dry_run:
        return {"method": "cli", "dry_run": True,
                "commands": [install_cmd, restart_cmd]}
    if not _have("openclaw"):
        return {"method": "cli", "rc": 127, "error": "openclaw CLI not on PATH",
                "next_steps": [" ".join(install_cmd), " ".join(restart_cmd)]}
    rc_install, log_install = _run_logged(install_cmd, "webwright-openclaw-install")
    rc_restart, log_restart = _run_logged(restart_cmd, "webwright-openclaw-restart")
    return {
        "method": "cli",
        "rc": rc_install,
        "log": log_install,
        "restart_rc": rc_restart,
        "restart_log": log_restart,
        "verify": "openclaw plugins list | grep webwright",
    }


def _register_hermes_source(clone_path: Path, *, dry_run: bool) -> dict[str, Any]:
    skill_src = clone_path / "skills" / "webwright"
    link = _hermes_skill_link()
    if dry_run:
        return {"method": "symlink", "dry_run": True,
                "source": str(skill_src), "link": str(link)}
    if not skill_src.exists():
        return {"method": "symlink", "error": f"source skill dir missing: {skill_src}"}
    try:
        link.parent.mkdir(parents=True, exist_ok=True)
        if link.is_symlink() or link.exists():
            try:
                link.unlink()
            except OSError as exc:
                return {"method": "symlink", "error": f"could not replace {link}: {exc}"}
        os.symlink(skill_src, link, target_is_directory=True)
    except OSError as exc:
        # Windows requires developer mode OR admin to create symlinks.
        if sys.platform == "win32":
            return {
                "method": "symlink",
                "error": (
                    "symlink creation failed on Windows; enable Developer Mode "
                    f"or run as admin, then symlink {skill_src} -> {link} "
                    f"manually. ({exc})"
                ),
                "skipped": True,
            }
        return {"method": "symlink", "error": str(exc)}
    return {"method": "symlink", "path": str(link), "source": str(skill_src)}


# ---------------------------------------------------------------------------
# Source-mode prerequisite steps (clone + pip + playwright)
# ---------------------------------------------------------------------------


def _source_prepare(result: dict[str, Any], *, dry_run: bool) -> Path | None:
    """Clone or update the Webwright checkout and run pip + playwright install."""
    if not _have("git"):
        result["error"] = "git not found in PATH"
        return None

    clone_path = paths.data_dir() / CLONE_DIRNAME
    result["clone_path"] = str(clone_path)

    if dry_run:
        result["steps"].append({"step": "dry-run", "clone_path": str(clone_path)})
        return clone_path

    # 1. Clone or update.
    if clone_path.exists() and (clone_path / ".git").exists():
        rc, log = _run_logged(
            ["git", "-C", str(clone_path), "pull", "--ff-only"],
            "webwright-pull",
        )
        result["steps"].append({"step": "git-pull", "rc": rc, "log": log})
        if rc != 0:
            return None
    else:
        if clone_path.exists():
            result["error"] = f"{clone_path} exists and is not a git checkout"
            return None
        rc, log = _run_logged(
            ["git", "clone", "--depth", "1", REPO_URL, str(clone_path)],
            "webwright-clone",
        )
        result["steps"].append({"step": "git-clone", "rc": rc, "log": log})
        if rc != 0:
            return None

    # 2. pip install --user -e <clone>.
    python = sys.executable
    rc, log = _run_logged(
        [python, "-m", "pip", "install", "--user", "-e", str(clone_path)],
        "webwright-pip-install",
    )
    result["steps"].append({"step": "pip-install", "rc": rc, "log": log})
    if rc != 0:
        return None

    # 3. Playwright chromium install (non-fatal).
    rc, log = _run_logged(
        [python, "-m", "playwright", "install", "chromium"],
        "webwright-playwright-install",
    )
    result["steps"].append({"step": "playwright-install-chromium", "rc": rc, "log": log})
    return clone_path


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def install(
    *,
    mode: str = "marketplace",
    hosts: list[str] | None = None,
    cooldown_days: int = 7,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Install Webwright into one or more hosts.

    Parameters
    ----------
    mode:
        ``marketplace`` (default) registers ``microsoft/Webwright`` with the
        host's plugin loader. ``source`` clones the repo locally and registers
        the local path; required for ``openclaw`` and ``hermes``.
    hosts:
        Subset of ``claude``, ``codex``, ``openclaw``, ``hermes``. Defaults to
        ``['claude', 'codex']``.
    cooldown_days:
        Accepted for API symmetry. Webwright ships from git/pip, not npm, so
        this value is currently informational.
    dry_run:
        Print the plan without executing any side-effects.
    """
    del cooldown_days  # not applicable to git/pip/marketplace flows

    if mode not in VALID_MODES:
        return {
            "tool": "webwright",
            "ok": False,
            "error": f"unknown mode: {mode!r} (expected one of {VALID_MODES})",
        }

    valid_hosts, invalid_hosts = _normalize_hosts(hosts)
    if invalid_hosts:
        return {
            "tool": "webwright",
            "ok": False,
            "error": f"unknown host(s): {invalid_hosts} (valid: {list(VALID_HOSTS)})",
        }
    if not valid_hosts:
        return {
            "tool": "webwright",
            "ok": False,
            "error": "no hosts selected",
        }

    result: dict[str, Any] = {
        "tool": "webwright",
        "mode": mode,
        "hosts": valid_hosts,
        "clone_path": None,
        "steps": [],
        "env": _check_api_keys(),
        "host_status": {},
        "ok": False,
    }
    if dry_run:
        result["dry_run"] = True

    if not any(result["env"].values()):
        print(
            "[webwright] WARNING: none of OPENAI_API_KEY, ANTHROPIC_API_KEY, "
            "OPENROUTER_API_KEY are set. Webwright requires one to operate.",
            file=sys.stderr,
        )

    if mode == "marketplace":
        # Refuse source-only hosts cleanly.
        for host in valid_hosts:
            if host in SOURCE_ONLY_HOSTS:
                result["host_status"][host] = _reject_source_only_host(host)

        for host in valid_hosts:
            if host in result["host_status"]:  # already rejected
                continue
            if host == "claude":
                result["host_status"]["claude"] = _register_claude_marketplace()
            elif host == "codex":
                result["host_status"]["codex"] = _register_codex_marketplace(dry_run=dry_run)

        result["ok"] = _hosts_ok(result["host_status"])
        return result

    # mode == "source"
    clone_path = _source_prepare(result, dry_run=dry_run)
    if clone_path is None and not dry_run:
        return result

    # In dry_run, clone_path may be valid even though we didn't actually clone.
    if clone_path is None:
        clone_path = paths.data_dir() / CLONE_DIRNAME

    for host in valid_hosts:
        if host == "claude":
            result["host_status"]["claude"] = _register_claude_source(clone_path)
        elif host == "codex":
            result["host_status"]["codex"] = _register_codex_source(clone_path, dry_run=dry_run)
        elif host == "openclaw":
            result["host_status"]["openclaw"] = _register_openclaw_source(clone_path, dry_run=dry_run)
        elif host == "hermes":
            result["host_status"]["hermes"] = _register_hermes_source(clone_path, dry_run=dry_run)

    result["ok"] = _hosts_ok(result["host_status"])
    return result


def _hosts_ok(host_status: dict[str, dict[str, Any]]) -> bool:
    """A host is OK if it has no ``error`` and (if it ran a CLI) rc == 0."""
    if not host_status:
        return False
    for status in host_status.values():
        if "error" in status:
            return False
        rc = status.get("rc")
        if rc is not None and rc != 0:
            return False
    return True


def uninstall(
    *,
    hosts: list[str] | None = None,
    keep_source: bool = True,
) -> dict[str, Any]:
    """Remove Webwright registration from the given hosts.

    Parameters
    ----------
    hosts:
        Subset of valid hosts. Defaults to all four.
    keep_source:
        When ``False``, also delete the ``<data_dir>/webwright`` clone (only
        if it lives inside this skill's managed data directory).
    """
    if hosts is None:
        valid_hosts = list(VALID_HOSTS)
        invalid_hosts: list[str] = []
    else:
        valid_hosts, invalid_hosts = _normalize_hosts(hosts)
    if invalid_hosts:
        return {
            "tool": "webwright",
            "ok": False,
            "error": f"unknown host(s): {invalid_hosts} (valid: {list(VALID_HOSTS)})",
        }

    result: dict[str, Any] = {
        "tool": "webwright",
        "action": "uninstall",
        "hosts": valid_hosts,
        "host_status": {},
        "source_removed": False,
        "ok": False,
    }

    for host in valid_hosts:
        if host == "claude":
            result["host_status"]["claude"] = {
                "method": "slash-commands",
                "next_steps": [f"/plugin uninstall {PLUGIN_ID.split('@')[0]}"],
                "note": "Slash commands cannot be issued from Python.",
            }
        elif host == "codex":
            if _have("codex"):
                rc, log = _run_logged(
                    ["codex", "plugin", "uninstall", "webwright"],
                    "webwright-codex-uninstall",
                )
                # Accept non-zero rc as benign (plugin may not be installed).
                result["host_status"]["codex"] = {
                    "method": "cli", "rc": rc, "log": log, "benign_failure": rc != 0,
                }
            else:
                result["host_status"]["codex"] = {"method": "cli", "rc": 127,
                                                  "skipped": "codex CLI not on PATH"}
        elif host == "openclaw":
            if _have("openclaw"):
                rc, log = _run_logged(
                    ["openclaw", "plugins", "uninstall", "webwright"],
                    "webwright-openclaw-uninstall",
                )
                result["host_status"]["openclaw"] = {
                    "method": "cli", "rc": rc, "log": log, "benign_failure": rc != 0,
                }
            else:
                result["host_status"]["openclaw"] = {"method": "cli", "rc": 127,
                                                     "skipped": "openclaw CLI not on PATH"}
        elif host == "hermes":
            link = _hermes_skill_link()
            removed = False
            if link.is_symlink() or link.exists():
                try:
                    target = os.readlink(link) if link.is_symlink() else None
                except OSError:
                    target = None
                managed_root = str(paths.data_dir())
                if target is None or managed_root in (target or ""):
                    try:
                        link.unlink()
                        removed = True
                    except OSError as exc:
                        result["host_status"]["hermes"] = {
                            "method": "symlink", "error": str(exc),
                        }
                        continue
                else:
                    result["host_status"]["hermes"] = {
                        "method": "symlink",
                        "skipped": (
                            f"{link} does not point into managed data dir "
                            f"({managed_root}); leaving untouched."
                        ),
                    }
                    continue
            result["host_status"]["hermes"] = {
                "method": "symlink",
                "removed": removed,
                "path": str(link),
            }

    if not keep_source:
        clone_path = paths.data_dir() / CLONE_DIRNAME
        managed_root = paths.data_dir().resolve()
        try:
            target_resolved = clone_path.resolve()
        except OSError:
            target_resolved = clone_path
        if clone_path.exists() and managed_root in target_resolved.parents:
            try:
                shutil.rmtree(clone_path)
                result["source_removed"] = True
                result["source_path"] = str(clone_path)
            except OSError as exc:
                result["source_error"] = str(exc)

    result["ok"] = all("error" not in s for s in result["host_status"].values())
    return result
