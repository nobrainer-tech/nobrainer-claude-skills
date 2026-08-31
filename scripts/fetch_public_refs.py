#!/usr/bin/env python3
"""Fetch public remote refs without changing the working tree."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


REMOTE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _git(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Update one public remote-tracking ref; leave the worktree untouched."
    )
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--branch", default="main")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if REMOTE_RE.fullmatch(args.remote) is None or args.remote.startswith("-"):
        print("PUBLIC_FETCH: ERROR: invalid remote name", file=sys.stderr)
        return 2
    if args.branch.startswith("-"):
        print("PUBLIC_FETCH: ERROR: invalid branch name", file=sys.stderr)
        return 2

    root_result = _git("rev-parse", "--show-toplevel")
    if root_result.returncode != 0:
        print("PUBLIC_FETCH: ERROR: not a Git worktree", file=sys.stderr)
        return 2
    root = Path(root_result.stdout.strip())

    branch_result = _git("check-ref-format", "--branch", args.branch, cwd=root)
    if branch_result.returncode != 0:
        print("PUBLIC_FETCH: ERROR: invalid branch name", file=sys.stderr)
        return 2

    refspec = f"refs/heads/{args.branch}:refs/remotes/{args.remote}/{args.branch}"
    fetch_result = _git("fetch", "--no-tags", args.remote, refspec, cwd=root)
    if fetch_result.returncode != 0:
        print(
            f"PUBLIC_FETCH: ERROR: fetch failed (exit {fetch_result.returncode})",
            file=sys.stderr,
        )
        return fetch_result.returncode or 1

    print(f"PUBLIC_FETCH: PASS remote={args.remote} branch={args.branch}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
