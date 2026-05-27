"""Atlassian MCP backend — orchestrator-driven.

We cannot invoke MCP tools from inside Python (the MCP runtime lives in the
host LLM). Instead, this client returns *instructions* that the orchestrator
LLM executes via its own ``mcp__atlassian_*`` tool calls and then writes
results back via :meth:`record_result`.

Contract for the orchestrator:

1. Call :meth:`pending_calls` to get the list of MCP calls required.
2. Execute each call using the host MCP runtime; filter tools through
   ``policies.read_only_jira.filter_tools`` first.
3. Call :meth:`record_result(call_id, payload)` for each response.
4. Re-invoke the original method (``search_issues`` / ``get_issue``) to read
   the materialised result.

The on-disk cache lives under
``<data>/jira-mcp-bridge/<company>/<call_id>.json``.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Optional

from .. import paths
from ..policies import read_only_jira
from .client import JiraClient


# Strict allowlist for any value interpolated into a bridge filename.
_CALL_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def _validate_call_id(call_id: str) -> None:
    if not isinstance(call_id, str) or not _CALL_ID_RE.match(call_id):
        raise ValueError(f"invalid call_id: {call_id!r}")


class MCPPolicyError(PermissionError):
    """Raised when an MCP tool name fails the read-only policy filter."""


def _is_read_only(tool: str) -> bool:
    return bool(tool) and tool in read_only_jira.filter_tools([tool])


def _bridge_dir(company: str) -> Path:
    d = paths.data_dir() / "jira-mcp-bridge" / company
    d.mkdir(parents=True, exist_ok=True)
    return d


class AtlassianMCPClient(JiraClient):
    backend_name = "atlassian-mcp"

    def __init__(
        self,
        company: str | None = None,
        server_url: str = "",
        *,
        bridge_dir: Path | None = None,
    ) -> None:
        # ``bridge_dir`` is accepted for tests / callers that want to inject a
        # tempdir without touching ``paths.data_dir()``.
        self.company = company or ""
        self.server_url = server_url
        if bridge_dir is not None:
            bridge_dir.mkdir(parents=True, exist_ok=True)
            self._bridge = bridge_dir
        else:
            self._bridge = _bridge_dir(self.company)

    def _call_id(self, tool: str, args: dict[str, Any]) -> str:
        payload = json.dumps({"tool": tool, "args": args}, sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def _quarantine(self, req: Path, reason: str) -> None:
        """Move a rejected request file out of the bridge dir for forensics."""
        try:
            target = req.with_name(
                f"{req.name}.rejected-{paths.now_utc_compact()}"
            )
            req.rename(target)
            print(
                f"[atlassian-mcp] quarantined {req.name} ({reason}) -> {target.name}",
                file=sys.stderr,
            )
        except OSError as exc:
            print(
                f"[atlassian-mcp] could not quarantine {req}: {exc}",
                file=sys.stderr,
            )

    def _request(self, tool: str, args: dict[str, Any]) -> Optional[Any]:
        if not _is_read_only(tool):
            raise MCPPolicyError(
                f"refusing to schedule mutating MCP tool: {tool!r}"
            )
        cid = self._call_id(tool, args)
        # ``cid`` is sha256[:16] of stdlib hashlib output — always hex, always
        # 16 chars — but validate defensively because every other filename
        # builder in this class does.
        _validate_call_id(cid)
        result_file = self._bridge / f"{cid}.result.json"
        if result_file.exists():
            try:
                return json.loads(result_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return None
        request_file = self._bridge / f"{cid}.request.json"
        paths.atomic_write_json(
            request_file,
            {"tool": tool, "args": args, "server_url": self.server_url},
            sort_keys=False,
        )
        return None

    def pending_calls(self) -> list[dict]:
        """Return queued request payloads, re-validating the policy on read.

        A tampered or stale ``*.request.json`` whose ``tool`` field has been
        replaced with a mutating tool is quarantined to ``*.rejected-<ts>`` and
        omitted from the returned list. The write-time guard in
        :meth:`_request` raises before such a file can be created normally —
        re-validating here is defence in depth against on-disk tampering.
        """
        out: list[dict] = []
        for req in sorted(self._bridge.glob("*.request.json")):
            if not req.name.endswith(".request.json"):
                continue
            cid = req.stem.split(".", 1)[0]
            try:
                _validate_call_id(cid)
            except ValueError:
                self._quarantine(req, "invalid call_id")
                continue
            if (self._bridge / f"{cid}.result.json").exists():
                continue
            try:
                payload = json.loads(req.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict):
                self._quarantine(req, "payload not an object")
                continue
            tool = payload.get("tool")
            if not isinstance(tool, str) or not _is_read_only(tool):
                self._quarantine(req, f"policy-blocked tool {tool!r}")
                continue
            out.append(payload | {"call_id": cid})
        return out

    def record_result(self, call_id: str, payload: Any) -> None:
        _validate_call_id(call_id)
        target = self._bridge / f"{call_id}.result.json"
        paths.atomic_write_json(target, payload, sort_keys=False, default=str)

    def search_issues(self, jql: str, max_results: int = 50) -> list[dict]:
        result = self._request(
            "atlassian_search_jira",
            {"jql": jql, "max_results": max_results, "server_url": self.server_url},
        )
        if result is None:
            return []
        if isinstance(result, dict) and "issues" in result:
            return list(result["issues"])
        if isinstance(result, list):
            return result
        return []

    def get_issue(self, key: str) -> Optional[dict]:
        result = self._request(
            "atlassian_get_jira_issue",
            {"issue_key": key, "server_url": self.server_url},
        )
        if isinstance(result, dict):
            return result
        return None

    def get_current_user(self) -> Optional[dict]:
        result = self._request(
            "atlassian_get_user",
            {"current": True, "server_url": self.server_url},
        )
        if isinstance(result, dict):
            return result
        return None
