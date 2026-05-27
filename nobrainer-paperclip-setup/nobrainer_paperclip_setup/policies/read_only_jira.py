"""Read-only Jira contract.

Two layers:
1. Tool allowlist — ``filter_tools`` keeps only read-style MCP tools.
2. System prompt clause — ``inject_into_prompt`` prepends the absolute rules.
"""

from __future__ import annotations

import fnmatch

READ_ONLY_CLAUSE: str = (
    "ABSOLUTE RULES - NEVER VIOLATE:\n"
    "1. You MUST NOT write to Jira (no comments, transitions, attachments, field updates).\n"
    "2. You MUST NOT push to remote, create PRs, or merge branches.\n"
    "3. You MAY read ticket data from the local cache at the path provided.\n"
    "4. You MAY work inside the provided worktree only.\n"
    "5. You MUST propose next actions in the HTML report - do not execute them.\n"
)

READ_PATTERNS: list[str] = [
    "*search*",
    "*get_*",
    "*list_*",
    "*read_*",
    "*find_*",
    "*lookup*",
    "*query*",
    "*describe*",
]

MUTATING_PATTERNS: list[str] = [
    "*create*",
    "*update*",
    "*transition*",
    "*add_*",
    "*delete*",
    "*remove*",
    "*move*",
    "*post_*",
    "*put_*",
    "*patch_*",
    "*comment*",
    "*assign*",
    "*attach*",
    "*set_*",
    "*edit*",
    "*write*",
    "*log_*",
    "*worklog*",
    "*archive*",
    "*restore*",
    "*rank_*",
    "*clone*",
    "*link_*",
    "*unlink*",
    "*upload*",
    "*close_*",
    "*resolve*",
    "*reopen*",
    "*flag_*",
    "*vote*",
    "*watch_*",
    "*unwatch*",
    "*subscribe*",
    "*unsubscribe*",
    "*publish*",
]


def _matches_any(name: str, patterns: list[str]) -> bool:
    lower = name.lower()
    return any(fnmatch.fnmatch(lower, p) for p in patterns)


def filter_tools(tools: list[str]) -> list[str]:
    """Keep only read-style tools. Mutating patterns always win."""
    allowed: list[str] = []
    for t in tools:
        if _matches_any(t, MUTATING_PATTERNS):
            continue
        if _matches_any(t, READ_PATTERNS):
            allowed.append(t)
    return allowed


def inject_into_prompt(base_prompt: str) -> str:
    if READ_ONLY_CLAUSE in base_prompt:
        return base_prompt
    return f"{READ_ONLY_CLAUSE}\n{base_prompt}".strip() + "\n"
