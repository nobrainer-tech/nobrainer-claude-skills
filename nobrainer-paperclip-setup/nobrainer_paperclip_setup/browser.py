"""Chromium-based browser detection and CDP launcher.

Supports Chrome, Edge, and Brave — they share the CDP wire protocol so the
launch args are identical. ``launch`` always returns a ``subprocess.Popen``
and never blocks; callers decide when to terminate.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional


def detect_available() -> dict[str, Optional[Path]]:
    """Locate Chromium binaries by OS. Returns ``{name: Path | None}``."""
    result: dict[str, Optional[Path]] = {"chrome": None, "edge": None, "brave": None}
    candidates: dict[str, list[Path]] = {"chrome": [], "edge": [], "brave": []}

    if sys.platform == "darwin":
        candidates["chrome"] = [
            Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        ]
        candidates["edge"] = [
            Path("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
        ]
        candidates["brave"] = [
            Path("/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"),
        ]
    elif sys.platform == "win32":
        pf = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        pf86 = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
        local = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData/Local")))
        candidates["chrome"] = [
            pf / "Google" / "Chrome" / "Application" / "chrome.exe",
            pf86 / "Google" / "Chrome" / "Application" / "chrome.exe",
            local / "Google" / "Chrome" / "Application" / "chrome.exe",
        ]
        candidates["edge"] = [
            pf86 / "Microsoft" / "Edge" / "Application" / "msedge.exe",
            pf / "Microsoft" / "Edge" / "Application" / "msedge.exe",
        ]
        candidates["brave"] = [
            pf / "BraveSoftware" / "Brave-Browser" / "Application" / "brave.exe",
            local / "BraveSoftware" / "Brave-Browser" / "Application" / "brave.exe",
        ]
    else:
        path_lookup = {
            "chrome": ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"],
            "edge": ["microsoft-edge", "microsoft-edge-stable"],
            "brave": ["brave-browser", "brave"],
        }
        for name, bins in path_lookup.items():
            for b in bins:
                found = shutil.which(b)
                if found:
                    candidates[name].append(Path(found))
                    break

    for name, options in candidates.items():
        for opt in options:
            if opt.exists():
                result[name] = opt
                break
    return result


def first_available(preferred: str = "chrome") -> tuple[str, Optional[Path]]:
    available = detect_available()
    if available.get(preferred):
        return preferred, available[preferred]
    for name in ("chrome", "edge", "brave"):
        if available.get(name):
            return name, available[name]
    return preferred, None


def launch(
    binary: Path,
    profile_dir: Path,
    cdp_port: int,
    headed: bool = True,
    extra_args: Optional[list[str]] = None,
) -> subprocess.Popen:
    """Launch a Chromium browser with CDP enabled. Returns the Popen handle."""
    profile_dir.mkdir(parents=True, exist_ok=True)
    args: list[str] = [
        str(binary),
        f"--user-data-dir={profile_dir}",
        f"--remote-debugging-port={cdp_port}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-features=GlobalMediaControls,MediaRouter",
    ]
    if not headed:
        args.append("--headless=new")
    if extra_args:
        args.extend(extra_args)

    # DECISION: detach stdin/stdout so the child survives parent exit. Logs are
    # discarded — Chromium is noisy and we never reason over its stderr.
    return subprocess.Popen(  # noqa: S603
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )


def is_session_alive(cdp_port: int, host: str = "127.0.0.1", timeout: float = 0.5) -> bool:
    """Probe CDP HTTP endpoint to see if a browser is listening."""
    try:
        with urllib.request.urlopen(  # noqa: S310
            f"http://{host}:{cdp_port}/json/version", timeout=timeout
        ) as resp:
            json.loads(resp.read().decode("utf-8", errors="replace"))
            return True
    except (urllib.error.URLError, json.JSONDecodeError, OSError, TimeoutError):
        return False


def port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)
    try:
        return sock.connect_ex((host, port)) == 0
    finally:
        sock.close()


def _current_username() -> str:
    """Resolve the effective POSIX username without importing ``pwd`` at top."""
    name = os.environ.get("USER") or os.environ.get("LOGNAME")
    if name:
        return name
    if sys.platform != "win32":
        try:
            import pwd  # lazy: POSIX-only stdlib module
            return pwd.getpwuid(os.getuid()).pw_name
        except (KeyError, OSError, ImportError):
            return ""
    return ""


def kill_by_profile(profile_dir: Path) -> int:
    """Best-effort: terminate any browser process bound to this profile dir.

    Filters by the current UID so we never SIGTERM another user's Chrome on
    shared hosts. After signalling, sleeps briefly to give Chromium time to
    flush its profile lock before any subsequent rmtree.

    Returns the number of processes signalled. No-op on Windows (would require
    WMI or PowerShell ``Get-CimInstance``).
    """
    if sys.platform == "win32":
        # REQUIRES: pywin32 or PowerShell ``Get-CimInstance Win32_Process``
        # DECISION: skip silently — relogin flow opens a new window anyway.
        return 0
    try:
        res = subprocess.run(
            ["ps", "-A", "-o", "pid=,user=,command="],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return 0
    if res.returncode != 0:
        return 0
    me = _current_username()
    killed = 0
    needle = f"--user-data-dir={profile_dir}"
    for line in res.stdout.splitlines():
        if needle not in line:
            continue
        parts = line.strip().split(None, 2)
        if len(parts) < 3 or not parts[0].isdigit():
            continue
        pid_str, user, _cmdline = parts
        if me and user != me:
            continue
        try:
            os.kill(int(pid_str), 15)
            killed += 1
        except (OSError, ProcessLookupError, ValueError):
            pass
    if killed:
        # Give Chromium a moment to release the profile lock before callers rmtree.
        import time
        time.sleep(1.0)
    return killed
