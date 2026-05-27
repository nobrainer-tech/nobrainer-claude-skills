"""Wire the Playwright MCP server into Codex CLI.

Strategy:
  1. Try ``codex mcp add playwright npx "@playwright/mcp@<safe_version>"``.
  2. If the CLI is missing or returns non-zero, fall back to editing
     ``~/.codex/config.toml`` atomically.

TOML editing is conservative: we preserve everything outside the
``[mcp_servers.playwright]`` block. We do NOT round-trip the whole file
through a parser (stdlib has no TOML *writer*); instead we locate the section
by line scan and splice in a freshly serialized block.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .. import paths

SERVER_NAME = "playwright"
NPM_PACKAGE = "@playwright/mcp"
SECTION_HEADER = "[mcp_servers.playwright]"

# Header detection: matches both forms ``[mcp_servers.playwright]`` and any
# other top-level table header (so we know where our block ends).
_HEADER_RE = re.compile(r"^\s*\[[^\[\]]+\]\s*$")
# Array-of-tables: ``[[name]]`` — ends our section just like a normal header.
_ARRAY_HEADER_RE = re.compile(r"^\s*\[\[[^\[\]]+\]\]\s*$")


def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    exe = shutil.which(cmd[0])
    if exe is None:
        return (127, "", f"{cmd[0]}: not found")
    try:
        proc = subprocess.run(  # noqa: S603
            [exe, *cmd[1:]],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return (proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip())
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return (1, "", str(exc))


def _spec(safe_version: str) -> str:
    return f"{NPM_PACKAGE}@{safe_version}"


def _toml_escape_string(s: str) -> str:
    """Escape a TOML basic string. Stdlib has no writer; this is enough for our case."""
    out = []
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def _render_section(spec: str) -> str:
    """Render an idiomatic ``[mcp_servers.playwright]`` block."""
    command_line = f"command = {_toml_escape_string('npx')}"
    args_line = f"args = [{_toml_escape_string(spec)}]"
    return "\n".join([SECTION_HEADER, command_line, args_line]) + "\n"


def _find_section(lines: list[str]) -> tuple[int, int] | None:
    """Return ``(start, end_exclusive)`` of the playwright MCP block, or None.

    The block starts at the header line and ends at the next header line
    (table or array-of-tables), or EOF. Any blank trailing line is included so
    a clean delete leaves no orphan blank line.
    """
    start = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped == SECTION_HEADER:
            start = i
            break
    if start is None:
        return None
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if _HEADER_RE.match(lines[j]) or _ARRAY_HEADER_RE.match(lines[j]):
            end = j
            break
    # Trim trailing blank lines inside the block (but stop before another header).
    while end > start + 1 and lines[end - 1].strip() == "":
        end -= 1
    return (start, end)


def _splice(original: str, replacement: str) -> str:
    """Insert or replace the playwright block, preserving everything else."""
    # ``splitlines(keepends=True)`` so we don't lose the trailing newline shape.
    lines = original.splitlines(keepends=True)
    section = _find_section([ln.rstrip("\n").rstrip("\r") for ln in lines])
    if section is None:
        # Append. Ensure exactly one blank line separator if file is non-empty
        # and doesn't already end with a newline.
        prefix = original
        if prefix and not prefix.endswith("\n"):
            prefix += "\n"
        if prefix and not prefix.endswith("\n\n"):
            prefix += "\n"
        return prefix + replacement

    start, end = section
    # Preserve leading blank line before our block if present in the prefix.
    head = "".join(lines[:start])
    tail = "".join(lines[end:])
    # Ensure tidy separators: exactly one newline between head and our block
    # (head may already end with \n), and a blank line before tail if tail is
    # non-empty and doesn't already start with a blank line.
    if head and not head.endswith("\n"):
        head += "\n"
    out = head + replacement
    if tail:
        if not out.endswith("\n"):
            out += "\n"
        if not tail.startswith("\n"):
            out += "\n"
        out += tail
    return out


def _remove_section(original: str) -> tuple[str, bool]:
    lines = original.splitlines(keepends=True)
    section = _find_section([ln.rstrip("\n").rstrip("\r") for ln in lines])
    if section is None:
        return original, False
    start, end = section
    head = "".join(lines[:start])
    tail = "".join(lines[end:])
    # Collapse double blank lines at the seam.
    if head.endswith("\n\n") and tail.startswith("\n"):
        tail = tail.lstrip("\n")
    return head + tail, True


def wire_playwright_mcp(
    safe_version: str,
    *,
    config_path: Path | None = None,
    force_fallback: bool = False,
) -> dict[str, Any]:
    """Register the Playwright MCP server with Codex.

    Args:
        safe_version: Version string (or ``"latest"``) that npm_safe resolved.
        config_path: Override ``~/.codex/config.toml``; used by tests.
        force_fallback: Skip the CLI attempt (used by tests and ``--method=toml``).
    """
    spec = _spec(safe_version)

    cli_error: str | None = None
    if not force_fallback and shutil.which("codex") is not None:
        rc, out, err = _run(["codex", "mcp", "add", SERVER_NAME, "npx", spec])
        if rc == 0:
            return {
                "method": "cli",
                "rc": 0,
                "path": None,
                "spec": spec,
                "server": SERVER_NAME,
                "stdout": out,
            }
        cli_error = err or out or f"rc={rc}"
    elif not force_fallback:
        cli_error = "codex CLI not found"

    path = config_path if config_path is not None else paths.codex_config_file()
    original = ""
    if path.exists():
        try:
            original = path.read_text(encoding="utf-8")
        except OSError:
            original = ""
    new_section = _render_section(spec)
    new_body = _splice(original, new_section)
    paths.atomic_write_text(path, new_body)
    return {
        "method": "config.toml",
        "rc": 0,
        "path": str(path),
        "spec": spec,
        "server": SERVER_NAME,
        "cli_error": cli_error,
    }


def unwire_playwright_mcp(
    *,
    config_path: Path | None = None,
) -> dict[str, Any]:
    """Remove the Playwright MCP server from Codex."""
    removed_cli = False
    if shutil.which("codex") is not None:
        rc, _out, _err = _run(["codex", "mcp", "remove", SERVER_NAME])
        removed_cli = rc == 0

    path = config_path if config_path is not None else paths.codex_config_file()
    removed_toml = False
    if path.exists():
        try:
            original = path.read_text(encoding="utf-8")
        except OSError:
            original = ""
        new_body, removed_toml = _remove_section(original)
        if removed_toml:
            paths.atomic_write_text(path, new_body)

    return {
        "method": "cli" if removed_cli else ("config.toml" if removed_toml else "none"),
        "removed_cli": removed_cli,
        "removed_toml": removed_toml,
        "path": str(path),
        "server": SERVER_NAME,
    }
