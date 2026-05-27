"""Verification helpers — emit a plan for an LLM driver (Playwright MCP).

We do not call MCP directly from Python. ``verification_plan`` returns
markdown that the orchestrator can hand to a Claude / Codex agent which then
invokes ``mcp__playwright__*`` tool calls. ``run_via_agent_browser`` is the
subprocess fallback when MCP is unreachable.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Any


def verification_plan(state: dict[str, Any]) -> str:
    company = state.get("company", "?")
    repo = state.get("repo", "?")
    paperclip_url = state.get("paperclip", {}).get("url", "http://localhost:3100")
    lines: list[str] = []
    lines.append(f"# Verification plan: {company}/{repo}")
    lines.append("")
    lines.append("Run these tool calls in order. Stop on first FAIL.")
    lines.append("")
    lines.append("## 1. Paperclip UI loads")
    lines.append(f"- `mcp__playwright__browser_navigate` -> {paperclip_url}")
    lines.append("- `mcp__playwright__browser_snapshot`")
    lines.append("- Assert page title contains 'Paperclip' and no '500' / 'error' banner.")
    lines.append("")
    lines.append("## 2. Per-agent identity check")
    for agent in state.get("agents", []):
        aid = agent.get("id")
        pc_id = agent.get("paperclip_agent_id") or "<missing>"
        cdp = agent.get("cdp_port")
        lines.append(f"### Agent {aid} (paperclip_agent_id={pc_id})")
        lines.append(f"- `mcp__playwright__browser_navigate` -> {paperclip_url}/agents/{pc_id}")
        lines.append("- `mcp__playwright__browser_snapshot`")
        lines.append(f"- Assert agent name contains '{company}-{repo}-agent-{aid}'.")
        lines.append(f"- Assert CDP port label shows {cdp}.")
        lines.append("")
    lines.append("## 3. Smoke task")
    lines.append("- Pick agent 1, send a trivial task via the UI:")
    lines.append("  ```")
    lines.append('  echo "hello" and exit 0')
    lines.append("  ```")
    lines.append("- Poll for 60 seconds. Assert status == COMPLETED.")
    lines.append("")
    lines.append("## 4. Report")
    lines.append(
        "- Write PASS/FAIL summary to "
        "`<logs>/<company>/<repo>/verify-<UTC-ts>.md` with screenshots inline."
    )
    return "\n".join(lines) + "\n"


def run_via_agent_browser(state: dict[str, Any]) -> dict[str, Any]:
    """Subprocess fallback. Requires the standalone ``agent-browser`` CLI."""
    if not shutil.which("agent-browser"):
        return {
            "ok": False,
            "reason": "agent-browser CLI not in PATH",
            "fallback": "manual",
        }
    paperclip_url = state.get("paperclip", {}).get("url", "http://localhost:3100")
    try:
        proc = subprocess.run(  # noqa: S603
            ["agent-browser", "verify", "--url", paperclip_url, "--json"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        return {
            "ok": proc.returncode == 0,
            "rc": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return {"ok": False, "reason": str(exc)}


def summarize_results(results: dict[str, Any]) -> str:
    if results.get("ok"):
        return "PASS"
    reason = results.get("reason") or results.get("stderr") or "unknown"
    return f"FAIL: {reason}"
