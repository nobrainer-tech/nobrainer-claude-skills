"""Per-backend Paperclip adapter config + agent system prompt builder."""

from __future__ import annotations

from pathlib import Path
from string import Template

from . import paths
from .policies import read_only_jira


SUPPORTED_BACKENDS = ("codex-cli", "opencode-copilot")


def agent_config(backend_name: str) -> dict:
    """Return the Paperclip ``backend`` block for a given backend name."""
    if backend_name == "codex-cli":
        return {
            "adapter": "codex_local",
            "command": "codex",
            "model": "gpt-5-codex",
            "args": ["--non-interactive"],
        }
    if backend_name == "opencode-copilot":
        return {
            "adapter": "opencode_local",
            "command": "opencode",
            "model": "gpt-5-codex",
            "args": ["run"],
            "auth": {"provider": "github-copilot"},
        }
    raise ValueError(f"unsupported backend: {backend_name!r}")


def _load_base_prompt() -> str:
    p = paths.templates_dir() / "agent_system_prompt.md"
    if p.exists():
        return p.read_text(encoding="utf-8")
    return ""


def system_prompt(
    company: str,
    repo: str,
    agent_id: int,
    ticket_path: Path,
    worktree_path: Path,
    report_path: Path,
) -> str:
    base = _load_base_prompt()
    rendered = Template(base).safe_substitute(
        company=company,
        repo=repo,
        agent_id=agent_id,
        ticket_path=str(ticket_path),
        worktree_path=str(worktree_path),
        report_path=str(report_path),
    )
    return read_only_jira.inject_into_prompt(rendered)
