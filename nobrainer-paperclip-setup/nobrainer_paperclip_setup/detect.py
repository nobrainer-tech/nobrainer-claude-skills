"""Cross-platform host state detection.

Pure read — no mutations. Returns a dict ready for ``json.dumps``. Designed so
an LLM can reason over the snapshot via
``python -m nobrainer_paperclip_setup detect --json``.

Avoids ``lsof``, ``pgrep``, ``fcntl``, and other non-portable tools. Everything
works through stdlib: ``socket``, ``subprocess``, ``shutil``, ``urllib.request``,
``pathlib``.
"""

from __future__ import annotations

import json
import platform
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Optional

from . import browser as browser_mod, credentials, paths, preferences

CDP_POOL_START = 19840
CDP_POOL_END = 19899
SCHEDULER_LABEL_PREFIX = "dev.nobrainer.paperclipsetup"
DEFAULT_PAPERCLIP_URL = "http://localhost:3100"


def _run(cmd: list[str], timeout: float = 5.0) -> tuple[int, str, str]:
    """Run a command; never raise. Returns ``(rc, stdout, stderr)``."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return 127, "", str(exc)


def _version_of(binary: str, flag: str = "--version") -> str:
    if not shutil.which(binary):
        return "missing"
    rc, out, err = _run([binary, flag])
    if rc != 0:
        return "missing"
    text = (out or err).strip()
    return text.splitlines()[0] if text else "unknown"


def _http_alive(url: str, timeout: float = 2.0) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
            return 200 <= resp.status < 500
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
        return False


def _port_listening(port: int, host: str = "127.0.0.1") -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)
    try:
        return sock.connect_ex((host, port)) == 0
    finally:
        sock.close()


def _detect_paperclip(url: str = DEFAULT_PAPERCLIP_URL) -> dict:
    status = "down"
    version = "unknown"
    if _http_alive(f"{url}/api/health") or _http_alive(url):
        status = "up"
        try:
            with urllib.request.urlopen(f"{url}/api/version", timeout=2) as resp:  # noqa: S310
                body = json.loads(resp.read().decode("utf-8", errors="replace"))
                version = body.get("version", "unknown")
        except Exception:  # noqa: BLE001 — best effort
            pass
    return {"url": url, "status": status, "version": version}


def _detect_backends() -> dict:
    codex = "yes" if shutil.which("codex") else "no"
    opencode = "yes" if shutil.which("opencode") else "no"
    gh_copilot = "no"
    if shutil.which("gh"):
        rc, out, _ = _run(["gh", "extension", "list"])
        if rc == 0 and "copilot" in out.lower():
            gh_copilot = "yes"
        else:
            rc, out, _ = _run(["gh", "auth", "status"])
            if rc == 0 and "copilot" in out.lower():
                gh_copilot = "yes"
    return {"codex_cli": codex, "opencode": opencode, "gh_copilot": gh_copilot}


def _detect_browsers() -> dict[str, Optional[str]]:
    """Stringify the canonical browser detection."""
    return {name: (str(p) if p else None) for name, p in browser_mod.detect_available().items()}


def _detect_companies() -> list[dict]:
    out: list[dict] = []
    for c in preferences.load().get("companies", []):
        out.append({
            "slug": c.get("slug"),
            "display_name": c.get("display_name"),
            "repos": list(c.get("repos", [])),
            "jira_enabled": bool(c.get("jira", {}).get("enabled")),
        })
    return out


def _detect_configured_repos() -> list[dict]:
    from . import state as state_mod

    out: list[dict] = []
    for s in state_mod.list_all():
        out.append({
            "company": s.get("company"),
            "repo": s.get("repo"),
            "repo_path": s.get("repo_path"),
            "framework": s.get("framework", "unknown"),
            "agents": len(s.get("agents", [])),
        })
    return out


def _detect_cdp_pool() -> dict:
    from . import state as state_mod

    used_configured: set[int] = set()
    for s in state_mod.list_all():
        for agent in s.get("agents", []):
            port = agent.get("cdp_port")
            if isinstance(port, int):
                used_configured.add(port)

    used_listening = {p for p in range(CDP_POOL_START, CDP_POOL_END + 1) if _port_listening(p)}
    taken = used_configured | used_listening
    total = CDP_POOL_END - CDP_POOL_START + 1
    return {
        "pool_start": CDP_POOL_START,
        "pool_end": CDP_POOL_END,
        "used_configured": sorted(used_configured),
        "used_listening": sorted(used_listening),
        "free_count": total - len(taken),
    }


def _detect_browser_profiles() -> list[str]:
    root = paths.browser_profiles_dir()
    return sorted(p.name for p in root.iterdir() if p.is_dir())


def _detect_scheduler_labels() -> list[str]:
    from .scheduler import current

    try:
        return sorted(current().list_labels(prefix=SCHEDULER_LABEL_PREFIX))
    except Exception:  # noqa: BLE001 — keep detect non-fatal
        return []


def _detect_mcps() -> dict:
    if sys.platform == "win32":
        rc, out, _ = _run(["tasklist", "/FO", "CSV", "/NH"])
        names = out.splitlines()
    else:
        rc, out, _ = _run(["ps", "-A", "-o", "pid=,command="])
        names = out.splitlines()

    result: dict[str, Optional[str]] = {"playwright_mcp": None, "atlassian_mcp": None}
    if rc != 0:
        return result

    for line in names:
        lower = line.lower()
        if result["playwright_mcp"] is None and "@playwright/mcp" in lower:
            result["playwright_mcp"] = _first_pid(line)
        if result["atlassian_mcp"] is None and (
            "atlassian-mcp" in lower or "atlassian_mcp" in lower or "mcp-atlassian" in lower
        ):
            result["atlassian_mcp"] = _first_pid(line)
    return result


def _first_pid(line: str) -> Optional[str]:
    for token in line.replace(",", " ").split():
        if token.strip('"').isdigit():
            return token.strip('"')
    return None


def _detect_credentials_path() -> Optional[str]:
    p = credentials.get_env_path()
    return str(p) if p else None


def detect_all(paperclip_url: str = DEFAULT_PAPERCLIP_URL) -> dict:
    prefs = preferences.load()
    return {
        "timestamp": paths.now_utc_iso(),
        "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "python": sys.version.split()[0],
        "node": _version_of("node", "-v"),
        "pnpm": _version_of("pnpm", "-v"),
        "git": _version_of("git", "--version"),
        "paperclip": _detect_paperclip(paperclip_url),
        "backends": _detect_backends(),
        "browsers": _detect_browsers(),
        "onboarded": prefs.get("onboarded_at") is not None,
        "orchestrator_workspace": prefs.get("orchestrator_workspace"),
        "companies": _detect_companies(),
        "configured_repos": _detect_configured_repos(),
        "cdp_pool": _detect_cdp_pool(),
        "browser_profiles": _detect_browser_profiles(),
        "scheduler_labels": _detect_scheduler_labels(),
        "credentials_env_path": _detect_credentials_path(),
        "mcps": _detect_mcps(),
    }


def next_free_cdp_ports(count: int, snapshot: Optional[dict] = None) -> list[int]:
    snapshot = snapshot or {"cdp_pool": _detect_cdp_pool()}
    taken = set(snapshot["cdp_pool"]["used_configured"]) | set(
        snapshot["cdp_pool"]["used_listening"]
    )
    free: list[int] = []
    for port in range(snapshot["cdp_pool"]["pool_start"], snapshot["cdp_pool"]["pool_end"] + 1):
        if port not in taken:
            free.append(port)
            if len(free) == count:
                break
    if len(free) < count:
        raise RuntimeError(
            f"Not enough free CDP ports in pool: needed {count}, got {len(free)}"
        )
    return free


if __name__ == "__main__":  # pragma: no cover
    json.dump(detect_all(), sys.stdout, indent=2, sort_keys=True, default=str)
    sys.stdout.write("\n")
