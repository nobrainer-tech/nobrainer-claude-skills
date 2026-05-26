"""Paperclip backup GC. Keeps last N hours, never deletes the last surviving file."""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Optional

from . import paperclip_api, paths


CANDIDATE_DIRS: list[Path] = [
    Path.home() / ".paperclip" / "backups",
    paths.data_dir() / "paperclip" / "backups",
]


_BACKUP_EXTS: set[str] = {".sql", ".gz", ".zip", ".tar", ".dump", ".bak", ".sqlite"}
_SAFE_PREFIXES: tuple[str, ...] = ("backup", "paperclip-", "pc-backup", "snapshot")
_FORBIDDEN_ROOTS: set[Path] = {Path.home(), Path("/"), Path("/tmp"), Path("/var")}


def _is_relative_to(child: Path, parent: Path) -> bool:
    """Backport of ``Path.is_relative_to`` for py<3.9."""
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _looks_like_backup_dir(p: Path) -> bool:
    """Sanity gate before any delete: directory must look like a Paperclip backup dir.

    Rules:
    - Resolved path must be a strict descendant of ``$HOME`` (never $HOME itself).
    - Must not be a forbidden root (``/``, ``/tmp``, ``/var``, ``$HOME``).
    - Must contain at least one file matching a backup naming/extension pattern.
    """
    try:
        resolved = p.resolve()
    except OSError:
        return False
    if resolved in _FORBIDDEN_ROOTS or resolved == Path("/"):
        return False
    home = Path.home().resolve()
    if resolved == home or not _is_relative_to(resolved, home):
        return False
    try:
        sample = [f for f in resolved.iterdir() if f.is_file()][:50]
    except OSError:
        return False
    if not sample:
        return False
    return any(
        f.name.lower().startswith(_SAFE_PREFIXES)
        or f.suffix.lower() in _BACKUP_EXTS
        for f in sample
    )


def find_backup_dir() -> Optional[Path]:
    """Try the Paperclip API first, then fall back to known locations."""
    api = paperclip_api.PaperclipAPI()
    if api.health():
        d = api.get_backup_dir()
        if d:
            p = Path(d).expanduser()
            if p.exists():
                return p
    for cand in CANDIDATE_DIRS:
        if cand.exists():
            return cand
    return None


def gc(
    retention_hours: int = 48,
    min_keep: int = 1,
    dry_run: bool = False,
    backup_dir: Optional[Path] = None,
) -> dict:
    """Delete backup files older than ``retention_hours``; always keep ``min_keep``."""
    target = backup_dir or find_backup_dir()
    if target is None:
        print("[backups-gc] no backup directory found", file=sys.stderr)
        return {"deleted": [], "kept": [], "total_bytes_freed": 0, "backup_dir": None}

    if not _looks_like_backup_dir(target):
        msg = f"[backups-gc] refusing to GC {target}: does not look like a backup dir"
        print(msg, file=sys.stderr)
        return {
            "refused": True,
            "reason": "target does not look like a backup dir",
            "path": str(target),
            "deleted": [],
            "kept": [],
            "total_bytes_freed": 0,
            "backup_dir": str(target),
        }

    try:
        files = sorted(
            (p for p in target.iterdir() if p.is_file()),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
    except OSError as exc:
        print(f"[backups-gc] iterdir failed on {target}: {exc}", file=sys.stderr)
        return {
            "deleted": [], "kept": [], "total_bytes_freed": 0,
            "backup_dir": str(target),
            "error": str(exc),
        }
    now = time.time()
    cutoff = now - retention_hours * 3600

    keepers: list[Path] = []
    candidates_to_delete: list[Path] = []
    for f in files:
        if len(keepers) < min_keep:
            keepers.append(f)
            continue
        if f.stat().st_mtime >= cutoff:
            keepers.append(f)
        else:
            candidates_to_delete.append(f)

    deleted: list[str] = []
    errors: list[dict[str, str]] = []
    bytes_freed = 0
    for f in candidates_to_delete:
        try:
            size = f.stat().st_size
        except OSError as exc:
            errors.append({"file": str(f), "error": f"stat: {exc}"})
            continue
        if not dry_run:
            try:
                f.unlink()
            except OSError as exc:
                print(f"[backups-gc] failed to delete {f}: {exc}", file=sys.stderr)
                errors.append({"file": str(f), "error": str(exc)})
                continue
        deleted.append(str(f))
        bytes_freed += size

    return {
        "backup_dir": str(target),
        "deleted": deleted,
        "kept": [str(p) for p in keepers],
        "errors": errors,
        "total_bytes_freed": bytes_freed,
        "ran_at": paths.now_utc_iso(),
        "dry_run": dry_run,
    }
