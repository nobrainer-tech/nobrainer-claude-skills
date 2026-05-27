"""Cross-platform path resolution + shared filesystem/time helpers.

Stdlib only. Mirrors the conventions used by ``nobrainer-paperclip-setup``:
XDG on Linux, ``Library/Application Support`` on macOS, ``%APPDATA%``/
``%LOCALAPPDATA%`` on Windows. Atomic writes via ``tempfile.mkstemp`` in the
destination directory with Windows-aware retry on ``PermissionError``.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

APP_NAME = "nobrainer-browser"

ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def now_utc_iso() -> str:
    """UTC timestamp in canonical ISO-8601 format (seconds precision)."""
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime(ISO_FORMAT)


def now_utc_compact() -> str:
    """UTC timestamp suitable for filenames (no colons)."""
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")


def slugify(value: str, *, separator: str = "-", case: str = "lower") -> str:
    """Filesystem-safe slug. Collapses non-alnum runs to ``separator``."""
    if separator == "-":
        charset = r"[^A-Za-z0-9_-]+"
    elif separator == "_":
        charset = r"[^A-Za-z0-9_]+"
    else:
        charset = r"[^A-Za-z0-9_]+"
    s = re.sub(charset, separator, value).strip(f"{separator}.")
    if case == "lower":
        s = s.lower()
    elif case == "upper":
        s = s.upper()
    return s or "default"


def _home() -> Path:
    return Path.home()


def config_dir() -> Path:
    """User configuration directory."""
    if sys.platform == "darwin":
        base = _home() / "Library" / "Application Support" / APP_NAME
    elif sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", _home() / "AppData" / "Roaming")) / APP_NAME
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", _home() / ".config")) / APP_NAME
    base.mkdir(parents=True, exist_ok=True)
    return base


def state_dir() -> Path:
    d = config_dir() / "state"
    d.mkdir(parents=True, exist_ok=True)
    return d


def data_dir() -> Path:
    """Persistent data (cloned repos, downloaded browsers)."""
    if sys.platform == "darwin":
        base = _home() / "Library" / "Application Support" / APP_NAME
    elif sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", _home() / "AppData" / "Local")) / APP_NAME
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", _home() / ".local" / "share")) / APP_NAME
    base.mkdir(parents=True, exist_ok=True)
    return base


def logs_dir() -> Path:
    if sys.platform == "darwin":
        base = _home() / "Library" / "Logs" / APP_NAME
    elif sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", _home() / "AppData" / "Local")) / APP_NAME / "Logs"
    else:
        base = Path(os.environ.get("XDG_STATE_HOME", _home() / ".local" / "state")) / APP_NAME / "logs"
    base.mkdir(parents=True, exist_ok=True)
    return base


def state_file() -> Path:
    return state_dir() / "state.json"


def claude_settings_file() -> Path:
    """Claude Code config: ``~/.claude.json``."""
    return _home() / ".claude.json"


def codex_config_file() -> Path:
    """Codex CLI config: ``~/.codex/config.toml``."""
    return _home() / ".codex" / "config.toml"


# ---------------------------------------------------------------------------
# Atomic write helpers
# ---------------------------------------------------------------------------

_WIN_RETRY_DELAYS_MS = (0, 50, 100, 200, 400)


def _atomic_replace(tmp: Path, target: Path) -> None:
    """Replace ``target`` with ``tmp`` atomically. Retries on Windows."""
    if sys.platform != "win32":
        tmp.replace(target)
        return
    last_exc: Exception | None = None
    for delay_ms in _WIN_RETRY_DELAYS_MS:
        if delay_ms:
            time.sleep(delay_ms / 1000)
        try:
            tmp.replace(target)
            return
        except PermissionError as exc:
            last_exc = exc
    assert last_exc is not None
    raise last_exc


def atomic_write_text(path: Path, content: str, *, mode: int | None = None) -> None:
    """Write ``content`` to ``path`` atomically. Creates parent dirs."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_str = tempfile.mkstemp(
        suffix=path.suffix + ".tmp",
        prefix=path.name + ".",
        dir=str(path.parent),
    )
    tmp = Path(tmp_str)
    try:
        if mode is not None and sys.platform != "win32":
            try:
                os.fchmod(fd, mode)
            except OSError:
                pass
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        _atomic_replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def atomic_write_json(
    path: Path,
    data: Any,
    *,
    indent: int = 2,
    sort_keys: bool = True,
) -> None:
    """Write ``data`` as JSON to ``path`` atomically."""
    text = json.dumps(data, indent=indent, sort_keys=sort_keys, ensure_ascii=False)
    atomic_write_text(path, text)


def load_json(path: Path) -> Any:
    """Load JSON from ``path``. Returns ``None`` if file missing or unreadable.

    Raises nothing on parse errors — quarantines the broken file and returns
    ``None`` so the caller can fall back to a fresh document.
    """
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        bak = path.with_name(f"{path.name}.broken-{now_utc_compact()}")
        try:
            path.rename(bak)
            print(
                f"[nobrainer-browser] WARNING: backed up corrupt {path} -> {bak} ({exc})",
                file=sys.stderr,
            )
        except OSError:
            pass
        return None


def log_path(action: str) -> Path:
    """Timestamped log file under ``logs_dir()/<UTC>-<action>.log``."""
    slug = slugify(action, separator="-")
    return logs_dir() / f"{now_utc_compact()}-{slug}.log"
