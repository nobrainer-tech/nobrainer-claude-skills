"""Credentials stored in a user-chosen .env file.

Location is persisted once in ``<config>/config.json`` under ``env_path``.
Default suggestion at first run: ``<cwd>/.env``.

Standard dotenv format: ``KEY=value`` per line. No shell expansion, no
multi-line values. Surrounding quotes are stripped. Stdlib only.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Optional

from . import paths

_LINE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def _load_config() -> dict:
    f = paths.config_file()
    if not f.exists():
        return {}
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except OSError:
        return {}
    except json.JSONDecodeError:
        paths.quarantine_broken(f)
        return {}


def _save_config(cfg: dict) -> None:
    paths.atomic_write_json(paths.config_file(), cfg)


def get_env_path() -> Optional[Path]:
    cfg = _load_config()
    p = cfg.get("env_path")
    return Path(p) if p else None


def set_env_path(path: Path) -> None:
    cfg = _load_config()
    cfg["env_path"] = str(path)
    _save_config(cfg)


def suggest_env_path(base: Optional[Path] = None) -> Path:
    return (base or Path.cwd()) / ".env"


def _parse_env_text(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        m = _LINE_RE.match(line)
        if not m:
            continue
        key, value = m.group(1), m.group(2)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        out[key] = value
    return out


def load() -> dict[str, str]:
    p = get_env_path()
    if p is None or not p.exists():
        return {}
    try:
        return _parse_env_text(p.read_text(encoding="utf-8"))
    except OSError:
        return {}


def get(key: str, default: Optional[str] = None) -> Optional[str]:
    """Process env wins, then .env file."""
    v = os.environ.get(key)
    if v is not None:
        return v
    return load().get(key, default)


def put(key: str, value: str) -> None:
    p = get_env_path()
    if p is None:
        raise RuntimeError(
            "Credentials .env path is not configured. Run the onboarding wizard "
            "or call nobrainer_paperclip_setup.credentials.set_env_path(...) first."
        )

    p.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    if p.exists():
        lines = p.read_text(encoding="utf-8").splitlines()

    new_lines: list[str] = []
    replaced = False
    for raw in lines:
        m = _LINE_RE.match(raw.strip().removeprefix("export "))
        if m and m.group(1) == key:
            new_lines.append(f"{key}={value}")
            replaced = True
        else:
            new_lines.append(raw)
    if not replaced:
        new_lines.append(f"{key}={value}")

    body = "\n".join(new_lines) + "\n"
    # Create the tmp file with 0o600 from the start so secrets are never
    # readable by other users between write and chmod (POSIX only — Windows
    # ACLs ignore the mode and use parent-dir inheritance).
    paths.atomic_write_text(p, body, mode=0o600)
    ensure_gitignored(p)


def delete(key: str) -> bool:
    p = get_env_path()
    if p is None or not p.exists():
        return False
    lines = p.read_text(encoding="utf-8").splitlines()
    kept: list[str] = []
    removed = False
    for raw in lines:
        m = _LINE_RE.match(raw.strip().removeprefix("export "))
        if m and m.group(1) == key:
            removed = True
            continue
        kept.append(raw)
    if removed:
        paths.atomic_write_text(p, "\n".join(kept) + "\n", mode=0o600)
    return removed


def _find_repo_root(start: Path) -> Optional[Path]:
    """Walk up from ``start`` looking for a ``.git`` entry. None if not in a repo."""
    cur = start
    while True:
        if (cur / ".git").exists():
            return cur
        if cur.parent == cur:
            return None
        cur = cur.parent


def ensure_gitignored(env_path: Path) -> Optional[Path]:
    """Append ``env_path.name`` to the nearest ``.gitignore`` inside the same
    git repo. If no ``.gitignore`` exists in the repo, create one at the repo
    root. Never escapes the repo boundary — outside-repo .env files are left
    alone with a warning.
    """
    target_name = env_path.name
    start = env_path.parent.resolve()
    repo_root = _find_repo_root(start)
    if repo_root is None:
        print(
            f"warning: {env_path} is not inside a git repo; not modifying any "
            ".gitignore",
            file=sys.stderr,
        )
        return None

    cur = start
    while True:
        candidate = cur / ".gitignore"
        if candidate.exists():
            content = candidate.read_text(encoding="utf-8")
            entries = {line.strip() for line in content.splitlines() if line.strip()}
            if target_name not in entries and f"/{target_name}" not in entries:
                with candidate.open("a", encoding="utf-8") as fh:
                    if not content.endswith("\n"):
                        fh.write("\n")
                    fh.write(f"{target_name}\n")
            return candidate
        if cur == repo_root:
            # No .gitignore anywhere in the chain — create one at the repo root.
            (repo_root / ".gitignore").write_text(
                f"{target_name}\n", encoding="utf-8",
            )
            return repo_root / ".gitignore"
        if cur.parent == cur:
            return None
        cur = cur.parent


def company_token_key(company_slug: str) -> str:
    """Convention: ``PAPERCLIP_TOKEN_<UPPER_SNAKE_SLUG>``."""
    return f"PAPERCLIP_TOKEN_{paths.slugify(company_slug, separator='_', case='upper')}"


def company_jira_pat_key(company_slug: str) -> str:
    """Convention: ``JIRA_PAT_<UPPER_SNAKE_SLUG>``."""
    return f"JIRA_PAT_{paths.slugify(company_slug, separator='_', case='upper')}"
