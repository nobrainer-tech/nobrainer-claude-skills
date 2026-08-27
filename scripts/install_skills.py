#!/usr/bin/env python3
"""Install active skills without overwriting an existing installation."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
CLIENT_DESTINATIONS = {
    "claude": Path.home() / ".claude" / "skills",
    "codex": Path.home() / ".codex" / "skills",
    "opencode": Path.home() / ".config" / "opencode" / "skills",
    "copilot": Path.home() / ".copilot" / "skills",
    "agents": Path.home() / ".agents" / "skills",
}


def available_skills() -> dict[str, Path]:
    return {
        path.parent.name: path.parent
        for path in sorted(SKILLS.glob("*/SKILL.md"))
    }


def existing_state(target: Path, source: Path, mode: str) -> str:
    if not target.exists() and not target.is_symlink():
        return "missing"
    if mode == "symlink" and target.is_symlink():
        try:
            if target.resolve(strict=True) == source.resolve(strict=True):
                return "current"
        except FileNotFoundError:
            pass
    return "conflict"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Dry-run or install NoBrainer skills into one client directory."
    )
    parser.add_argument("--client", choices=sorted(CLIENT_DESTINATIONS), required=True)
    parser.add_argument(
        "--dest",
        type=Path,
        help="Override the client destination (useful for controlled tests).",
    )
    parser.add_argument("--mode", choices=("symlink", "copy"), default="symlink")
    parser.add_argument(
        "--skill",
        action="append",
        dest="skills",
        help="Install only this skill; repeat for several. Default: all active skills.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Perform writes. Without this flag the command is a dry-run.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    catalogue = available_skills()
    requested = args.skills or sorted(catalogue)
    unknown = sorted(set(requested) - set(catalogue))
    if unknown:
        print(f"ERROR: unknown active skill(s): {', '.join(unknown)}", file=sys.stderr)
        return 2

    destination = (args.dest or CLIENT_DESTINATIONS[args.client]).expanduser().resolve()
    plan: list[tuple[str, Path, Path, str]] = []
    conflicts: list[Path] = []
    for name in requested:
        source = catalogue[name]
        target = destination / name
        state = existing_state(target, source, args.mode)
        plan.append((name, source, target, state))
        if state == "conflict":
            conflicts.append(target)

    for name, source, target, state in plan:
        action = "KEEP" if state == "current" else "CONFLICT" if state == "conflict" else args.mode.upper()
        print(f"{action}: {name}: {source} -> {target}")

    if conflicts:
        print("ERROR: refusing to overwrite existing targets", file=sys.stderr)
        return 3
    if not args.apply:
        print("DRY_RUN: no files changed; rerun with --apply to install")
        return 0

    destination.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []
    try:
        for _, source, target, state in plan:
            if state == "current":
                continue
            if args.mode == "symlink":
                os.symlink(source, target, target_is_directory=True)
                created.append(target)
            else:
                # Claim the target atomically before registering it as ours.
                # If another process wins the race after preflight, mkdir
                # raises and rollback must leave that foreign target alone.
                target.mkdir()
                created.append(target)
                shutil.copytree(source, target, dirs_exist_ok=True)

        for _, source, target, _ in plan:
            if not (target / "SKILL.md").is_file():
                raise RuntimeError(f"readback failed for {target}")
            if args.mode == "symlink" and target.resolve(strict=True) != source.resolve(strict=True):
                raise RuntimeError(f"symlink readback mismatch for {target}")
    except Exception as exc:
        rollback_errors: list[str] = []
        for target in reversed(created):
            try:
                if target.is_symlink() or target.is_file():
                    target.unlink()
                elif target.is_dir():
                    shutil.rmtree(target)
            except OSError as rollback_exc:
                rollback_errors.append(f"{target}: {rollback_exc}")
        if rollback_errors:
            print(
                "ERROR: installation failed and rollback was incomplete: "
                f"{exc}; leftovers: {'; '.join(rollback_errors)}",
                file=sys.stderr,
            )
        else:
            print(f"ERROR: installation rolled back: {exc}", file=sys.stderr)
        return 4

    print(f"OK: installed {len(created)} skill(s) for {args.client}; {len(plan) - len(created)} unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
