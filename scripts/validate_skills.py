#!/usr/bin/env python3
"""Validate portable skill structure and the NoBrainer canonical suite."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
LINK_RE = re.compile(r"\[[^\]]+\]\((?!https?://|#|mailto:)([^)]+)\)")

SUITE = {
    "nobrainer-ultra": "nb-ultra",
    "nobrainer-sessions": "nb-sessions",
    "nobrainer-spec-driven-development": "nb-sdd",
    "nobrainer-decide": "nb-decide",
    "nobrainer-rca": "nb-rca",
    "nobrainer-autoimprove": "nb-autoimprove",
    "nobrainer-wiki": "nb-wiki",
    "nobrainer-wiki-add": "nb-wiki-add",
    "nobrainer-wiki-get": "nb-wiki-get",
    "nobrainer-wiki-tidy": "nb-wiki-tidy",
}

LEGACY = {
    "deep-rca",
    "karpathy-auto-improver",
    "llm-wiki",
    "nobrainer-autopilot",
    "nobrainer-continuous-improvement",
    "nobrainer-memory",
    "nobrainer-starter",
    "nobrainer-team-builder",
    "nobrainer-ultracode-workflow",
    "wiki-add",
    "wiki-get",
    "wiki-tidy",
}

ACTIVE = set(SUITE) | {
    "agents-restraint",
    "codex-in-claude-code",
    "deep-audit",
    "deep-autoreview",
    "deep-bugs-finder",
    "nobrainer-browser",
    "nobrainer-fast-audit",
    "nobrainer-npm-secure",
    "nobrainer-reddit",
}

PUBLIC_FORBIDDEN = (
    "/Users/",
    "--dangerously-skip-permissions",
    "CLAUDE-CODE-FABLE",
)
PORTABLE_FRONTMATTER = {"name", "description"}


def parse_frontmatter(path: Path) -> tuple[dict[str, str], str]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        raise ValueError("frontmatter must start on line 1")
    try:
        end = lines.index("---", 1)
    except ValueError as exc:
        raise ValueError("frontmatter is not closed") from exc

    values: dict[str, str] = {}
    key: str | None = None
    chunks: list[str] = []
    for line in lines[1:end]:
        match = re.match(r"^([a-zA-Z0-9_-]+):(?:\s*(.*))?$", line)
        if match:
            if key is not None:
                values[key] = " ".join(chunks).strip().strip('"')
            key = match.group(1)
            raw = (match.group(2) or "").strip()
            chunks = [] if raw in {"", ">", ">-", "|", "|-"} else [raw]
        elif key is not None and line.startswith("  "):
            chunks.append(line.strip())
        elif line.strip():
            raise ValueError(f"unsupported frontmatter line: {line}")
    if key is not None:
        values[key] = " ".join(chunks).strip().strip('"')
    return values, text


def active_skill_files() -> list[Path]:
    return sorted(SKILLS.glob("*/SKILL.md"))


def validate(suite_only: bool) -> list[str]:
    errors: list[str] = []
    seen: dict[str, Path] = {}

    for path in active_skill_files():
        try:
            frontmatter, _ = parse_frontmatter(path)
        except ValueError as exc:
            errors.append(f"{path.relative_to(ROOT)}: {exc}")
            continue
        name = frontmatter.get("name", "")
        description = frontmatter.get("description", "")
        extra_keys = set(frontmatter) - PORTABLE_FRONTMATTER
        if extra_keys:
            errors.append(
                f"{path.relative_to(ROOT)}: non-portable frontmatter keys "
                f"{', '.join(sorted(extra_keys))}"
            )
        if not NAME_RE.fullmatch(name):
            errors.append(f"{path.relative_to(ROOT)}: invalid name {name!r}")
        if name != path.parent.name:
            errors.append(
                f"{path.relative_to(ROOT)}: name {name!r} does not match directory"
            )
        if not description or len(description) > 1024:
            errors.append(f"{path.relative_to(ROOT)}: invalid description length")
        if name in seen:
            errors.append(
                f"duplicate name {name!r}: {seen[name].relative_to(ROOT)} and "
                f"{path.relative_to(ROOT)}"
            )
        seen[name] = path

    if not suite_only:
        return errors

    active_names = {path.parent.name for path in active_skill_files()}
    if active_names != ACTIVE:
        missing = sorted(ACTIVE - active_names)
        extra = sorted(active_names - ACTIVE)
        errors.append(f"active inventory mismatch: missing={missing}, extra={extra}")

    for name, alias in SUITE.items():
        path = SKILLS / name / "SKILL.md"
        if not path.is_file():
            errors.append(f"missing canonical skill {name}")
            continue
        try:
            frontmatter, text = parse_frontmatter(path)
        except ValueError as exc:
            errors.append(f"{path.relative_to(ROOT)}: {exc}")
            continue
        if set(frontmatter) != PORTABLE_FRONTMATTER:
            errors.append(f"{path.relative_to(ROOT)}: suite frontmatter must contain only name and description")
        if not frontmatter.get("description", "").startswith("Use when"):
            errors.append(f"{path.relative_to(ROOT)}: description must start with 'Use when'")
        if alias not in frontmatter.get("description", ""):
            errors.append(f"{path.relative_to(ROOT)}: missing alias trigger {alias}")
        for forbidden in PUBLIC_FORBIDDEN:
            if forbidden in text:
                errors.append(f"{path.relative_to(ROOT)}: forbidden public value {forbidden!r}")
        for match in LINK_RE.finditer(text):
            target = match.group(1).split("#", 1)[0]
            if not target or target.startswith("/") or "$" in target:
                continue
            if not (path.parent / target).resolve().exists():
                errors.append(f"{path.relative_to(ROOT)}: broken relative link {target}")

    for name in LEGACY:
        if (SKILLS / name / "SKILL.md").exists():
            errors.append(f"legacy skill remains discoverable: {name}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", action="store_true", help="enforce canonical suite gates")
    args = parser.parse_args()
    errors = validate(args.suite)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    scope = "canonical suite" if args.suite else "active skills"
    print(f"OK: validated {scope}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
