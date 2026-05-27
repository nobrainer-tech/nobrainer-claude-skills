"""Git worktree helpers via subprocess. Never raise."""

from __future__ import annotations

import subprocess
from pathlib import Path


def _run(cmd: list[str], cwd: Path | None = None, timeout: float = 30.0) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True, text=True,
            timeout=timeout, check=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return 127, "", str(exc)


def create(repo_path: Path, company: str, agent_id: int, base_branch: str = "main") -> Path:
    """Create ``<repo_path>-<company>-agent-<N>`` worktree on a fresh branch.

    If the target directory already exists but is not a git worktree (no
    ``.git`` entry), it is removed and recreated. Branch creation uses the
    non-destructive ``-b`` flag; if the branch already exists git will fail
    loudly and the caller's rollback handler kicks in.
    """
    suffix = f"-{company}-agent-{agent_id}"
    worktree_path = repo_path.parent / f"{repo_path.name}{suffix}"
    branch = f"{company}/agent-{agent_id}"

    if worktree_path.exists():
        git_marker = worktree_path / ".git"
        if git_marker.exists():
            return worktree_path
        # Stale dir from a previous failed run — wipe and recreate.
        _rmtree(worktree_path)

    rc, _, err = _run(
        ["git", "worktree", "add", "-b", branch, str(worktree_path), base_branch],
        cwd=repo_path,
    )
    if rc != 0:
        first_err = err.strip()
        # Fall back to current HEAD if base_branch is missing. Still use ``-b``
        # so we never silently force-reset a branch the user cares about.
        rc, _, err = _run(
            ["git", "worktree", "add", "-b", branch, str(worktree_path)],
            cwd=repo_path,
        )
        if rc != 0:
            raise RuntimeError(
                "git worktree add failed: "
                f"{err.strip() or first_err or 'no error output'}"
            )
    # Paranoia: even if git returned 0, refuse to lie about the on-disk state.
    if not worktree_path.exists():
        raise RuntimeError(
            f"worktree path missing after `git worktree add`: {worktree_path}"
        )
    return worktree_path


def remove(worktree_path: Path) -> bool:
    if not worktree_path.exists():
        return False
    # Locate the controlling repo via the worktree's own git pointer.
    rc, top, _ = _run(["git", "-C", str(worktree_path), "rev-parse", "--git-common-dir"])
    repo_root: Path | None = None
    if rc == 0 and top.strip():
        common = Path(top.strip()).resolve()
        repo_root = common.parent if common.name == ".git" else common
        _run(["git", "worktree", "remove", "--force", str(worktree_path)], cwd=repo_root)
    if worktree_path.exists():
        # last resort: ``rm -rf`` via Python
        _rmtree(worktree_path)
    # Prune phantom worktree entries from the parent repo's metadata so a
    # subsequent ``git worktree add`` for the same path does not collide.
    if repo_root and repo_root.exists():
        _run(["git", "-C", str(repo_root), "worktree", "prune"])
    return not worktree_path.exists()


def _rmtree(p: Path) -> None:
    import shutil
    shutil.rmtree(p, ignore_errors=True)


def list_for(repo_path: Path) -> list[Path]:
    rc, out, _ = _run(["git", "-C", str(repo_path), "worktree", "list", "--porcelain"])
    if rc != 0:
        return []
    paths: list[Path] = []
    for line in out.splitlines():
        if line.startswith("worktree "):
            paths.append(Path(line.split(" ", 1)[1]))
    return paths


def is_healthy(worktree_path: Path) -> bool:
    if not worktree_path.exists():
        return False
    rc, _, _ = _run(
        ["git", "-C", str(worktree_path), "fsck", "--no-progress"],
        timeout=60.0,
    )
    return rc == 0


def ticket_branch(company: str, ticket_key: str) -> str:
    return f"{company}/{ticket_key}"
