"""Detect which browser-automation tools are installed and how they're wired.

Returns a single dict, JSON-serializable, with no secrets and no personal
data. The output is consumed by ``__main__.detect`` (CLI) and by ``verify``.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from . import paths


def _run(cmd: list[str], timeout: int = 10) -> tuple[int, str, str]:
    """Run ``cmd`` without a shell; return (rc, stdout, stderr)."""
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


def _platform_string() -> str:
    return f"{platform.system()} {platform.release()} ({platform.machine()})"


def _python_version() -> str:
    return ".".join(str(x) for x in sys.version_info[:3])


def _which_version(cmd: str, version_flag: str = "--version") -> str | None:
    if shutil.which(cmd) is None:
        return None
    rc, out, err = _run([cmd, version_flag])
    if rc != 0:
        return None
    text = out or err
    # Node-style: "v20.11.1"; npm: "10.5.0"; python: "Python 3.12.4".
    first = text.splitlines()[0].strip() if text else ""
    return first or None


# ---------------------------------------------------------------------------
# Per-tool detection
# ---------------------------------------------------------------------------


def _detect_webwright_plugin_registered() -> dict:
    """Best-effort: is the Webwright plugin registered with each host?"""
    home = Path.home()

    # Claude: ~/.claude/plugins/installed_plugins.json or similar.
    claude_registered = False
    claude_candidates = [
        home / ".claude" / "plugins" / "installed_plugins.json",
        home / ".claude" / "plugins.json",
    ]
    for cand in claude_candidates:
        if not cand.exists():
            continue
        data = paths.load_json(cand)
        if isinstance(data, dict):
            keys = data.keys()
            if any("webwright" in str(k).lower() for k in keys):
                claude_registered = True
                break
            plugins = data.get("plugins") or data.get("installed") or {}
            if isinstance(plugins, dict) and any(
                "webwright" in str(k).lower() for k in plugins
            ):
                claude_registered = True
                break
            if isinstance(plugins, list) and any(
                "webwright" in str(item).lower() for item in plugins
            ):
                claude_registered = True
                break
        elif isinstance(data, list):
            if any("webwright" in str(item).lower() for item in data):
                claude_registered = True
                break

    # Codex: ~/.codex/config.toml [plugins.webwright] or ~/.codex/plugins/webwright.
    codex_registered = False
    codex_cfg = paths.codex_config_file()
    if codex_cfg.exists():
        try:
            text = codex_cfg.read_text(encoding="utf-8")
            for line in text.splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if s.startswith("[plugins.webwright]") or s == "[plugins.webwright]":
                    codex_registered = True
                    break
        except OSError:
            pass
    if not codex_registered:
        codex_plugins_dir = home / ".codex" / "plugins"
        if codex_plugins_dir.exists():
            try:
                codex_registered = any(
                    "webwright" in p.name.lower() for p in codex_plugins_dir.iterdir()
                )
            except OSError:
                codex_registered = False

    # OpenClaw: shell `openclaw plugins list | grep webwright`.
    openclaw_registered = False
    if shutil.which("openclaw") is not None:
        rc, out, _ = _run(["openclaw", "plugins", "list"], timeout=10)
        if rc == 0 and "webwright" in out.lower():
            openclaw_registered = True

    # Hermes: ~/.hermes/skills/webwright (file or symlink).
    hermes_link = home / ".hermes" / "skills" / "webwright"
    hermes_registered = hermes_link.exists() or hermes_link.is_symlink()

    return {
        "claude": claude_registered,
        "codex": codex_registered,
        "openclaw": openclaw_registered,
        "hermes": hermes_registered,
    }


def detect_webwright() -> dict:
    """Look for a Webwright clone under ``data_dir()/webwright`` and host wiring."""
    clone = paths.data_dir() / "webwright"
    has_setup = clone.exists() and (
        (clone / "setup.py").exists() or (clone / "pyproject.toml").exists()
    )
    chromium = False
    # Best-effort: Playwright caches browsers in ~/Library/Caches/ms-playwright (mac),
    # ~/.cache/ms-playwright (linux), %USERPROFILE%\AppData\Local\ms-playwright (win).
    if sys.platform == "darwin":
        cache = Path.home() / "Library" / "Caches" / "ms-playwright"
    elif sys.platform == "win32":
        cache = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "ms-playwright"
    else:
        cache = Path.home() / ".cache" / "ms-playwright"
    if cache.exists():
        try:
            chromium = any(p.name.startswith("chromium") for p in cache.iterdir())
        except OSError:
            chromium = False

    plugin_registered = _detect_webwright_plugin_registered()
    any_host_registered = any(plugin_registered.values())

    return {
        "installed": bool(has_setup) or any_host_registered,
        "installed_from_source": bool(has_setup),
        "path": str(clone) if has_setup else None,
        "playwright_chromium": bool(chromium),
        "plugin_registered": plugin_registered,
    }


def detect_playwright_mcp() -> dict:
    """Playwright MCP is invoked via ``npx``; check state cache for safe pin."""
    state = paths.load_json(paths.state_file()) or {}
    pin = state.get("playwright_mcp_version")
    return {
        "installed": "via npx",
        "safe_version": pin,
    }


def detect_playwright_cli() -> dict:
    """Global ``playwright`` CLI."""
    version_line = _which_version("playwright")
    installed = version_line is not None
    browsers: list[str] = []
    # Probe browser cache for chromium/firefox/webkit folders.
    if sys.platform == "darwin":
        cache = Path.home() / "Library" / "Caches" / "ms-playwright"
    elif sys.platform == "win32":
        cache = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "ms-playwright"
    else:
        cache = Path.home() / ".cache" / "ms-playwright"
    if cache.exists():
        try:
            for child in cache.iterdir():
                name = child.name.lower()
                for browser in ("chromium", "firefox", "webkit"):
                    if name.startswith(browser) and browser not in browsers:
                        browsers.append(browser)
        except OSError:
            pass
    return {
        "installed": installed,
        "version": version_line,
        "browsers_installed": browsers,
    }


def detect_agent_browser() -> dict:
    """Look for the ``agent-browser`` binary on PATH."""
    version_line = _which_version("agent-browser")
    installed = version_line is not None
    # Chrome for Testing typically lands under the user's cache directory; we
    # use a portable best-effort probe.
    cft = False
    candidates = [
        Path.home() / ".cache" / "chrome-for-testing",
        Path.home() / "Library" / "Caches" / "chrome-for-testing",
        Path(os.environ.get("LOCALAPPDATA", "")) / "chrome-for-testing" if sys.platform == "win32" else None,
    ]
    for c in candidates:
        if c and c.exists():
            cft = True
            break
    return {
        "installed": installed,
        "version": version_line,
        "chrome_for_testing": cft,
    }


# ---------------------------------------------------------------------------
# Wiring detection
# ---------------------------------------------------------------------------


def _toml_has_playwright_mcp(text: str) -> bool:
    """Return True iff ``text`` declares ``[mcp_servers.playwright]``."""
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s == "[mcp_servers.playwright]" or s.startswith("[mcp_servers.playwright]"):
            return True
    return False


def detect_wiring() -> dict:
    """Inspect Claude + Codex config files for the playwright MCP entry."""
    claude_method = "none"
    claude_wired = False
    claude_path = paths.claude_settings_file()
    if claude_path.exists():
        data = paths.load_json(claude_path) or {}
        servers = data.get("mcpServers") or {}
        if isinstance(servers, dict) and "playwright" in servers:
            claude_wired = True
            claude_method = "settings.json"

    codex_method = "none"
    codex_wired = False
    codex_path = paths.codex_config_file()
    if codex_path.exists():
        try:
            text = codex_path.read_text(encoding="utf-8")
            if _toml_has_playwright_mcp(text):
                codex_wired = True
                codex_method = "config.toml"
        except OSError:
            pass

    return {
        "claude": {"playwright_mcp": claude_wired, "method": claude_method},
        "codex": {"playwright_mcp": codex_wired, "method": codex_method},
    }


def detect_env_keys() -> dict:
    keys = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENROUTER_API_KEY")
    return {k: bool(os.environ.get(k)) for k in keys}


def detect_all() -> dict:
    """Aggregate snapshot of host + tools + wiring."""
    return {
        "platform": _platform_string(),
        "python": _python_version(),
        "node": _which_version("node"),
        "npm": _which_version("npm"),
        "pip": _which_version("pip"),
        "tools": {
            "webwright": detect_webwright(),
            "playwright_mcp": detect_playwright_mcp(),
            "playwright_cli": detect_playwright_cli(),
            "agent_browser": detect_agent_browser(),
        },
        "wiring": detect_wiring(),
        "env": detect_env_keys(),
    }


if __name__ == "__main__":  # pragma: no cover
    print(json.dumps(detect_all(), indent=2, sort_keys=True))
