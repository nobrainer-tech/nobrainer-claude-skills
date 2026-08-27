#!/usr/bin/env python3
"""Validate portable skill structure and the NoBrainer canonical suite."""

from __future__ import annotations

import argparse
import json
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
    "nobrainer-wiki": "nb-wiki",
    "nobrainer-browser": "nb-browser",
    "nobrainer-autoimprove": "nb-autoimprove",
    "nobrainer-decide": "nb-decide",
    "nobrainer-rca": "nb-rca",
    "nobrainer-review": "nb-review",
}

LEGACY = {
    "add-gitleaks",
    "agent-browser",
    "agents-restraint",
    "codex-in-claude-code",
    "deep-audit",
    "deep-autoreview",
    "deep-bugs-finder",
    "deep-decide",
    "deep-rca",
    "karpathy-auto-improver",
    "karpathy-llm-wiki",
    "llm-wiki",
    "nb-add",
    "nb-get",
    "nb-tidy",
    "nobrainer-autopilot",
    "nobrainer-continuous-improvement",
    "nobrainer-memory",
    "nobrainer-memory-memsearch",
    "nobrainer-fast-audit",
    "nobrainer-npm-secure",
    "nobrainer-reddit",
    "nobrainer-starter",
    "nobrainer-team-builder",
    "nobrainer-ultracode-workflow",
    "nobrainer-wiki-add",
    "nobrainer-wiki-get",
    "nobrainer-wiki-tidy",
    "playwright-cli",
    "wiki-add",
    "wiki-get",
    "wiki-tidy",
}

ACTIVE = set(SUITE)

PUBLIC_FORBIDDEN = (
    "/Users/",
    "nobrainer-tech@",
    "--dangerously-skip-permissions",
    "CLAUDE-CODE-FABLE",
)
PORTABLE_FRONTMATTER = {"name", "description"}
PUBLIC_TEXT_SUFFIXES = {
    ".json",
    ".js",
    ".md",
    ".ps1",
    ".py",
    ".sh",
    ".svg",
    ".toml",
    ".yaml",
    ".yml",
}
PUBLIC_EXTENSIONLESS_FILES: set[Path] = set()
PUBLIC_ROOT_FILES = (
    ROOT / ".gitleaks.toml",
    ROOT / ".gitignore",
    ROOT / ".pre-commit-config.yaml",
    ROOT / "README.md",
    ROOT / "AGENTS.md",
    ROOT / "CLAUDE.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "LICENSE",
    ROOT / "SECURITY.md",
    ROOT / "plugin.json",
    ROOT / "package.json",
)
PUBLIC_ROOT_DIRS = (
    ROOT / "docs",
    ROOT / "assets",
    ROOT / ".agents",
    ROOT / ".claude-plugin",
    ROOT / ".codex-plugin",
    ROOT / ".cursor-plugin",
    ROOT / ".github",
    ROOT / ".opencode",
    ROOT / "scripts",
    ROOT / "tests",
)
DETECTOR_FIXTURE_FILES = {
    ROOT / "scripts" / "validate_skills.py",
    ROOT / "tests" / "test_suite.py",
}
VERSION_PATHS = (
    ROOT / "package.json",
    ROOT / "plugin.json",
    ROOT / ".claude-plugin" / "plugin.json",
    ROOT / ".codex-plugin" / "plugin.json",
    ROOT / ".cursor-plugin" / "plugin.json",
)


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


def is_public_text_file(path: Path) -> bool:
    return path.is_file() and (
        path.suffix.lower() in PUBLIC_TEXT_SUFFIXES
        or path in PUBLIC_EXTENSIONLESS_FILES
    )


def public_text_files() -> list[Path]:
    paths = {path for path in PUBLIC_ROOT_FILES if path.is_file()}
    for directory in PUBLIC_ROOT_DIRS:
        if not directory.is_dir():
            continue
        paths.update(
            path
            for path in directory.rglob("*")
            if is_public_text_file(path)
        )
    for skill in active_skill_files():
        paths.update(
            path
            for path in skill.parent.rglob("*")
            if is_public_text_file(path)
        )
    return sorted(paths)


def relative_link_errors(path: Path, text: str) -> list[str]:
    errors: list[str] = []
    for match in LINK_RE.finditer(text):
        target = match.group(1).split("#", 1)[0]
        if not target or target.startswith("/") or "$" in target:
            continue
        if not (path.parent / target).resolve().exists():
            errors.append(f"{path.relative_to(ROOT)}: broken relative link {target}")
    return errors


def public_scan_text(path: Path, text: str) -> str:
    """Remove the one intentional detector fixture, but scan every other use."""
    if path not in DETECTOR_FIXTURE_FILES:
        return text
    indent = "            " if path.name == "test_suite.py" else "    "
    for forbidden in PUBLIC_FORBIDDEN:
        fixture = f'{indent}"{forbidden}",'
        if text.count(fixture) != 1:
            return text
        text = text.replace(fixture, "", 1)
    return text


def validate(suite_only: bool) -> list[str]:
    errors: list[str] = []
    seen: dict[str, Path] = {}

    for path in active_skill_files():
        try:
            frontmatter, text = parse_frontmatter(path)
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
        errors.extend(relative_link_errors(path, text))

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
            frontmatter, _ = parse_frontmatter(path)
        except ValueError as exc:
            errors.append(f"{path.relative_to(ROOT)}: {exc}")
            continue
        if set(frontmatter) != PORTABLE_FRONTMATTER:
            errors.append(f"{path.relative_to(ROOT)}: suite frontmatter must contain only name and description")
        if not frontmatter.get("description", "").startswith("Use when"):
            errors.append(f"{path.relative_to(ROOT)}: description must start with 'Use when'")
        if alias not in frontmatter.get("description", ""):
            errors.append(f"{path.relative_to(ROOT)}: missing alias trigger {alias}")
    for name in LEGACY:
        if (SKILLS / name / "SKILL.md").exists():
            errors.append(f"legacy skill remains discoverable: {name}")

    for path in public_text_files():
        text = path.read_text(encoding="utf-8")
        scanned_text = public_scan_text(path, text)
        for forbidden in PUBLIC_FORBIDDEN:
            if forbidden in scanned_text:
                errors.append(
                    f"{path.relative_to(ROOT)}: forbidden public value {forbidden!r}"
                )
        if (
            path.suffix.lower() == ".md"
            and path.name != "SKILL.md"
        ):
            errors.extend(relative_link_errors(path, text))

    versions: dict[str, str] = {}
    for path in VERSION_PATHS:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{path.relative_to(ROOT)}: invalid version manifest: {exc}")
            continue
        version = data.get("version")
        if not isinstance(version, str) or not version:
            errors.append(f"{path.relative_to(ROOT)}: missing version")
            continue
        versions[str(path.relative_to(ROOT))] = version

    marketplace = ROOT / ".claude-plugin" / "marketplace.json"
    try:
        data = json.loads(marketplace.read_text(encoding="utf-8"))
        versions[str(marketplace.relative_to(ROOT))] = data["plugins"][0]["version"]
    except (OSError, json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
        errors.append(f"{marketplace.relative_to(ROOT)}: invalid plugin version: {exc}")

    if len(set(versions.values())) > 1:
        errors.append(f"manifest version mismatch: {versions}")

    codex_manifest = ROOT / ".codex-plugin" / "plugin.json"
    try:
        codex_data = json.loads(codex_manifest.read_text(encoding="utf-8"))
        if "hooks" in codex_data:
            errors.append(f"{codex_manifest.relative_to(ROOT)}: unsupported top-level hooks field")
        if codex_data.get("skills") != "./skills/":
            errors.append(f"{codex_manifest.relative_to(ROOT)}: skills path must be ./skills/")
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        errors.append(f"{codex_manifest.relative_to(ROOT)}: invalid Codex manifest: {exc}")

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
