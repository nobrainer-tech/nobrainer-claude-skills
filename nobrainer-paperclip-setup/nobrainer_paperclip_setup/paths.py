"""Cross-platform path resolution + shared filesystem/time helpers.

Mirrors the subset of ``platformdirs`` we actually need plus the canonical
``slugify``, ``now_utc_iso``, and atomic-write helpers used by every callsite
that touches preferences/state/credentials/scheduler files.

Stdlib only.
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

APP_NAME = "nobrainer-paperclip-setup"

ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def now_utc_iso() -> str:
    """UTC timestamp in canonical ISO-8601 format (seconds precision)."""
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime(ISO_FORMAT)


def now_utc_compact() -> str:
    """UTC timestamp suitable for filenames (no colons)."""
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")


def slugify(value: str, *, separator: str = "-", case: str = "lower") -> str:
    """Canonical slugify used across the package.

    Collapses runs of non-alnum (plus optional underscore) to ``separator``,
    strips leading/trailing separators and dots, and refuses pure-dot input.

    ``case``: ``"lower"`` (default), ``"upper"``, or ``"preserve"``.
    ``separator``: replacement string. Must not be alphanumeric.
    """
    if separator == "-":
        charset = r"[^A-Za-z0-9_-]+"
    elif separator == "_":
        charset = r"[^A-Za-z0-9_]+"
    else:
        # Generic fallback: keep alnum + underscore only.
        charset = r"[^A-Za-z0-9_]+"
    s = re.sub(charset, separator, value).strip(f"{separator}.")
    if case == "lower":
        s = s.lower()
    elif case == "upper":
        s = s.upper()
    return s or "default"


def _slug(value: str) -> str:
    """Filesystem-safe slug (backwards-compatible internal alias)."""
    return slugify(value, separator="-", case="lower")


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
    """Per-(company,repo) JSON state files live here."""
    d = config_dir() / "state"
    d.mkdir(parents=True, exist_ok=True)
    return d


def data_dir() -> Path:
    """Large or persistent data (browser profiles, ticket cache)."""
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


def browser_profiles_dir() -> Path:
    """Root of per-agent browser user-data directories."""
    d = data_dir() / "browser-profiles"
    d.mkdir(parents=True, exist_ok=True)
    return d


def company_log_dir(company: str, repo: str | None = None) -> Path:
    base = logs_dir() / _slug(company)
    if repo:
        base = base / _slug(repo)
    base.mkdir(parents=True, exist_ok=True)
    return base


def tickets_dir(company: str, repo: str) -> Path:
    """Per-repo ticket snapshot + report root."""
    d = company_log_dir(company, repo) / "tickets"
    d.mkdir(parents=True, exist_ok=True)
    return d


def evidence_dir(company: str, repo: str, ticket_key: str) -> Path:
    d = tickets_dir(company, repo) / _slug(ticket_key) / "evidence"
    d.mkdir(parents=True, exist_ok=True)
    return d


def ticket_report_dir(company: str, repo: str, ticket_key: str) -> Path:
    d = tickets_dir(company, repo) / _slug(ticket_key)
    d.mkdir(parents=True, exist_ok=True)
    return d


def ticket_cache_dir(company: str) -> Path:
    d = data_dir() / "ticket-cache" / _slug(company)
    d.mkdir(parents=True, exist_ok=True)
    return d


def config_file() -> Path:
    """Singleton config: env_path, repos_root, paperclip_url."""
    return config_dir() / "config.json"


def state_file(company: str, repo: str) -> Path:
    return state_dir() / f"{_slug(company)}__{_slug(repo)}.json"


def templates_dir() -> Path:
    """Templates packaged with the skill."""
    return Path(__file__).resolve().parent.parent / "templates"


# ---------------------------------------------------------------------------
# Atomic write helpers (tmp+rename). Used everywhere we persist to disk.
# ---------------------------------------------------------------------------

_WIN_RETRY_DELAYS_MS = (0, 50, 100, 200, 400)


def _atomic_replace(tmp: Path, target: Path) -> None:
    """Replace ``target`` with ``tmp`` atomically. Retries on Windows.

    Windows fails ``replace`` with PermissionError when the destination is held
    open by a reader. POSIX has no such race.
    """
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
    """Write ``content`` to ``path`` atomically. Creates parent dirs.

    If ``mode`` is given (POSIX only), the temp file is created with that mode
    from the start (no chmod-after-write race). Uses ``tempfile.mkstemp`` in
    the destination directory so concurrent writers to the same ``path`` get
    distinct temp filenames — a previous fixed ``path.with_suffix(".tmp")``
    scheme silently dropped one writer's content under contention.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_str = tempfile.mkstemp(
        suffix=path.suffix + ".tmp",
        prefix=path.name + ".",
        dir=str(path.parent),
    )
    tmp = Path(tmp_str)
    try:
        if mode is not None and sys.platform != "win32":
            # mkstemp creates the file 0o600 on POSIX. Apply the caller's mode
            # before any data is written so secrets are never world-readable
            # in the window between creation and close.
            try:
                os.fchmod(fd, mode)
            except OSError:
                pass
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        _atomic_replace(tmp, path)
    except BaseException:
        # Replace failed (or the writer raised) — clean up the orphan temp.
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
    default: Any = None,
) -> None:
    """Write ``data`` as JSON to ``path`` atomically. Creates parent dirs."""
    text = json.dumps(
        data,
        indent=indent,
        sort_keys=sort_keys,
        ensure_ascii=False,
        default=default,
    )
    atomic_write_text(path, text)


def quarantine_broken(path: Path) -> Path | None:
    """Rename a corrupt file out of the way with a timestamped ``.broken-...``
    suffix so callers can fall back to defaults without losing forensic data.

    Returns the backup path or ``None`` if nothing existed.
    """
    if not path.exists():
        return None
    bak = path.with_name(f"{path.name}.broken-{now_utc_compact()}")
    try:
        path.rename(bak)
    except OSError:
        return None
    print(
        f"[nobrainer-paperclip-setup] WARNING: backed up corrupt {path} -> {bak}",
        file=sys.stderr,
    )
    return bak
