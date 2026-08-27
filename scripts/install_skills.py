#!/usr/bin/env python3
"""Install active skills without overwriting an existing installation."""

from __future__ import annotations

import argparse
import ctypes
import os
import shutil
import stat
import sys
import tempfile
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

CURATED_SKILLS = frozenset(
    {
        "nobrainer-autoimprove",
        "nobrainer-browser",
        "nobrainer-decide",
        "nobrainer-rca",
        "nobrainer-review",
        "nobrainer-sessions",
        "nobrainer-spec-driven-development",
        "nobrainer-ultra",
        "nobrainer-wiki",
    }
)

# Names retired from the previous public layouts. A legacy symlink is
# migratable only when its name and target both match this table and this
# checkout; unknown targets remain conflicts and are never touched.
LEGACY_TO_CANONICAL = {
    "add-gitleaks": "nobrainer-review",
    "agent-browser": "nobrainer-browser",
    "agents-restraint": "nobrainer-ultra",
    "codex-in-claude-code": "nobrainer-ultra",
    "deep-audit": "nobrainer-review",
    "deep-autoreview": "nobrainer-review",
    "deep-bugs-finder": "nobrainer-review",
    "deep-decide": "nobrainer-decide",
    "deep-rca": "nobrainer-rca",
    "karpathy-auto-improver": "nobrainer-autoimprove",
    "karpathy-llm-wiki": "nobrainer-wiki",
    "llm-wiki": "nobrainer-wiki",
    "nb-add": "nobrainer-wiki",
    "nb-get": "nobrainer-wiki",
    "nb-tidy": "nobrainer-wiki",
    "nobrainer-autopilot": "nobrainer-ultra",
    "nobrainer-browser": "nobrainer-browser",
    "nobrainer-continuous-improvement": "nobrainer-autoimprove",
    "nobrainer-starter": "nobrainer-ultra",
    "nobrainer-fast-audit": "nobrainer-review",
    "nobrainer-memory": "nobrainer-wiki",
    "nobrainer-memory-memsearch": "nobrainer-wiki",
    "nobrainer-npm-secure": "nobrainer-review",
    "nobrainer-reddit": "nobrainer-ultra",
    "nobrainer-team-builder": "nobrainer-sessions",
    "nobrainer-ultracode-workflow": "nobrainer-ultra",
    "nobrainer-wiki-add": "nobrainer-wiki",
    "nobrainer-wiki-get": "nobrainer-wiki",
    "nobrainer-wiki-tidy": "nobrainer-wiki",
    "playwright-cli": "nobrainer-browser",
    "wiki-add": "nobrainer-wiki",
    "wiki-get": "nobrainer-wiki",
    "wiki-tidy": "nobrainer-wiki",
}


EntryFingerprint = tuple[int, int, int, str | None]


def entry_fingerprint(target: Path) -> EntryFingerprint | None:
    """Fingerprint one directory entry without following a symlink."""

    try:
        metadata = target.lstat()
        linked = os.readlink(target) if stat.S_ISLNK(metadata.st_mode) else None
    except OSError:
        return None
    return metadata.st_dev, metadata.st_ino, metadata.st_mode, linked


def is_exact_legacy_link(target: Path, legacy_name: str) -> bool:
    """Return whether target is the known stale link owned by this checkout."""

    return legacy_link_snapshot(target, legacy_name) is not None


def legacy_link_snapshot(
    target: Path, legacy_name: str
) -> EntryFingerprint | None:
    """Verify and fingerprint the same legacy symlink directory entry."""

    try:
        before = target.lstat()
        if not stat.S_ISLNK(before.st_mode):
            return None
        linked = os.readlink(target)
        after = target.lstat()
    except OSError:
        return None

    before_id = before.st_dev, before.st_ino, before.st_mode
    after_id = after.st_dev, after.st_ino, after.st_mode
    if before_id != after_id:
        return None

    resolved = Path(linked)
    if not resolved.is_absolute():
        resolved = target.parent / resolved
    known_sources = {
        (ROOT / legacy_name).resolve(strict=False),
        (SKILLS / legacy_name).resolve(strict=False),
    }
    if resolved.resolve(strict=False) not in known_sources:
        return None
    return before_id[0], before_id[1], before_id[2], linked


def legacy_name_for(target: Path, canonical: Path) -> str | None:
    """Return the known root-level predecessor referenced by a canonical target."""

    candidates = [canonical.name]
    candidates.extend(
        legacy_name
        for legacy_name, canonical_name in sorted(LEGACY_TO_CANONICAL.items())
        if canonical_name == canonical.name and legacy_name != canonical.name
    )
    canonical_source = canonical.resolve(strict=False)
    for legacy_name in candidates:
        old_source = (ROOT / legacy_name).resolve(strict=False)
        if old_source != canonical_source and is_exact_legacy_link(
            target, legacy_name
        ):
            return legacy_name
    return None


def claim_legacy_link(target: Path, legacy_name: str) -> Path:
    """Atomically move a candidate aside, then verify ownership before deletion."""

    expected = legacy_link_snapshot(target, legacy_name)
    if expected is None:
        raise RuntimeError(f"legacy link changed before claim: {target}")

    claim_dir = Path(
        tempfile.mkdtemp(prefix=".nobrainer-migration-", dir=target.parent)
    )
    claim = claim_dir / target.name
    try:
        target.rename(claim)
    except OSError as exc:
        claim_dir.rmdir()
        raise RuntimeError(f"legacy link changed after preflight: {target}") from exc

    claimed = entry_fingerprint(claim)

    # Compare the moved directory entry itself. Re-resolving a relative link
    # from claim.parent would change its base and reject a valid legacy link.
    if claimed == expected:
        return claim

    try:
        restore_claim(target, claim)
    except RuntimeError as exc:
        raise RuntimeError(
            f"legacy link changed after preflight; {exc}"
        ) from exc
    raise RuntimeError(
        f"legacy link changed after preflight; replacement restored at {target}"
    )


def atomic_rename_no_replace(source: Path, target: Path) -> None:
    """Rename one entry only when target is absent, using the native primitive."""

    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    target_bytes = os.fsencode(target)

    if sys.platform == "darwin":
        renamex = getattr(libc, "renamex_np", None)
        if renamex is None:
            raise RuntimeError("atomic no-replace rename is unavailable")
        renamex.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        renamex.restype = ctypes.c_int
        result = renamex(source_bytes, target_bytes, 0x00000004)  # RENAME_EXCL
    elif sys.platform.startswith("linux"):
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise RuntimeError("atomic no-replace rename is unavailable")
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            -100, source_bytes, -100, target_bytes, 0x00000001
        )  # AT_FDCWD, RENAME_NOREPLACE
    elif os.name == "nt":
        # Windows os.rename already refuses to replace an existing target.
        os.rename(source, target)
        return
    else:
        raise RuntimeError("atomic no-replace rename is unavailable")

    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), str(target))


def restore_claim(target: Path, claim: Path) -> None:
    """Restore a claimed entry atomically without replacing a new target."""

    fingerprint = entry_fingerprint(claim)
    if fingerprint is None:
        raise RuntimeError(f"missing or unreadable claim preserved at {claim}")
    try:
        if stat.S_ISLNK(fingerprint[2]):
            previous_link = fingerprint[3]
            if previous_link is None:
                raise RuntimeError(f"unreadable symlink claim preserved at {claim}")
            # os.symlink is an atomic create and fails with EEXIST if another
            # process installed a replacement.
            os.symlink(previous_link, target, target_is_directory=True)
        else:
            atomic_rename_no_replace(claim, target)
    except OSError as exc:
        raise RuntimeError(
            f"replacement preserved at {claim}; restore blocked by {target}"
        ) from exc
    except RuntimeError as exc:
        raise RuntimeError(f"replacement preserved at {claim}; {exc}") from exc

    if stat.S_ISLNK(fingerprint[2]):
        try:
            claim.unlink()
        except OSError as exc:
            raise RuntimeError(
                f"replacement restored at {target}; duplicate claim remains at {claim}"
            ) from exc
    try:
        claim.parent.rmdir()
    except OSError as exc:
        raise RuntimeError(
            f"replacement restored at {target}; claim directory remains at {claim.parent}"
        ) from exc


def available_skills() -> dict[str, Path]:
    return {
        path.parent.name: path.parent
        for path in sorted(SKILLS.glob("*/SKILL.md"))
    }


def existing_state(target: Path, source: Path, mode: str) -> str:
    if not target.exists() and not target.is_symlink():
        return "missing"
    if target.is_symlink():
        try:
            if mode == "symlink" and target.resolve(strict=True) == source.resolve(
                strict=True
            ):
                return "current"
        except FileNotFoundError:
            pass
        if legacy_name_for(target, source) is not None:
            return "legacy"
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
        help="Install only this skill; repeat for several. Default: all curated skills.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Perform writes. Without this flag the command is a dry-run.",
    )
    parser.add_argument(
        "--migrate-legacy",
        action="store_true",
        help=(
            "Migrate only exact stale symlinks from this checkout's previous "
            "root-level layout and renamed aliases."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    catalogue = available_skills()
    actual_inventory = set(catalogue)
    if actual_inventory != CURATED_SKILLS:
        missing = sorted(CURATED_SKILLS - actual_inventory)
        extra = sorted(actual_inventory - CURATED_SKILLS)
        print(
            f"ERROR: curated skill inventory drift: missing={missing}, extra={extra}",
            file=sys.stderr,
        )
        return 2

    requested = sorted(set(args.skills)) if args.skills else sorted(CURATED_SKILLS)
    unknown = sorted(set(requested) - CURATED_SKILLS)
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
        if state == "conflict" or (state == "legacy" and not args.migrate_legacy):
            conflicts.append(target)

    alias_plan: list[tuple[str, str, Path, str]] = []
    for legacy_name, canonical_name in sorted(LEGACY_TO_CANONICAL.items()):
        if legacy_name == canonical_name or canonical_name not in requested:
            continue
        target = destination / legacy_name
        if not target.exists() and not target.is_symlink():
            continue
        state = "legacy" if is_exact_legacy_link(target, legacy_name) else "conflict"
        alias_plan.append((legacy_name, canonical_name, target, state))
        if state == "conflict" or not args.migrate_legacy:
            conflicts.append(target)

    for name, source, target, state in plan:
        action = (
            "KEEP"
            if state == "current"
            else "CONFLICT"
            if state == "conflict"
            else "MIGRATE"
            if state == "legacy" and args.migrate_legacy
            else "LEGACY"
            if state == "legacy"
            else args.mode.upper()
        )
        print(f"{action}: {name}: {source} -> {target}")

    for legacy_name, canonical_name, target, state in alias_plan:
        action = (
            "MIGRATE_ALIAS"
            if state == "legacy" and args.migrate_legacy
            else "LEGACY_ALIAS"
            if state == "legacy"
            else "CONFLICT_ALIAS"
        )
        print(f"{action}: {legacy_name} -> {canonical_name}: {target}")

    if conflicts:
        has_unknown_conflict = any(state == "conflict" for _, _, _, state in plan) or any(
            state == "conflict" for _, _, _, state in alias_plan
        )
        has_migratable_legacy = any(
            state == "legacy" for _, _, _, state in plan
        ) or any(state == "legacy" for _, _, _, state in alias_plan)
        if has_migratable_legacy and not args.migrate_legacy and not has_unknown_conflict:
            print(
                "ERROR: legacy symlink detected; rerun with "
                "--migrate-legacy --apply",
                file=sys.stderr,
            )
        else:
            print("ERROR: refusing to overwrite existing targets", file=sys.stderr)
        return 3
    if not args.apply:
        suffix = (
            " with --migrate-legacy --apply"
            if any(state == "legacy" for _, _, _, state in plan)
            or any(state == "legacy" for _, _, _, state in alias_plan)
            else " with --apply"
        )
        print(f"DRY_RUN: no files changed; rerun{suffix} to install")
        return 0

    destination.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []
    migrated: list[tuple[Path, Path, str]] = []
    try:
        for legacy_name, _, target, state in alias_plan:
            if state != "legacy":
                continue
            claim = claim_legacy_link(target, legacy_name)
            migrated.append((target, claim, legacy_name))

        for _, source, target, state in plan:
            if state == "current":
                continue
            if state == "legacy":
                legacy_name = legacy_name_for(target, source)
                if legacy_name is None:
                    raise RuntimeError(f"legacy target changed after preflight: {target}")
                claim = claim_legacy_link(target, legacy_name)
                migrated.append((target, claim, legacy_name))
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
            if (
                args.mode == "symlink"
                and target.resolve(strict=True) != source.resolve(strict=True)
            ):
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
        for target, claim, _ in reversed(migrated):
            try:
                restore_claim(target, claim)
            except (OSError, RuntimeError) as rollback_exc:
                rollback_errors.append(
                    f"{target} (legacy preserved at {claim}): {rollback_exc}"
                )
        if rollback_errors:
            print(
                "ERROR: installation failed and rollback was incomplete: "
                f"{exc}; leftovers: {'; '.join(rollback_errors)}",
                file=sys.stderr,
            )
        else:
            print(f"ERROR: installation rolled back: {exc}", file=sys.stderr)
        return 4

    cleanup_errors: list[str] = []
    for _, claim, _ in migrated:
        try:
            claim.unlink()
            claim.parent.rmdir()
        except OSError as cleanup_exc:
            cleanup_errors.append(f"{claim}: {cleanup_exc}")
    if cleanup_errors:
        print(
            "WARNING: install succeeded, but legacy migration backups remain: "
            + "; ".join(cleanup_errors),
            file=sys.stderr,
        )

    print(
        f"OK: installed {len(created)} skill(s) for {args.client}; "
        f"{len(migrated)} legacy link(s) migrated; "
        f"{len(plan) - len(created)} unchanged"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
