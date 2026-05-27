"""Thin HTTP client for the local Paperclip server. Stdlib only.

Bearer token sourced from .env via ``credentials.get``. ``_request`` raises
:class:`PaperclipAPIError` on any failure; callers that want soft-fail
semantics wrap individual methods in try/except.

Error kinds:
- ``"http"``    — non-2xx HTTP status. ``.status`` is the integer code.
- ``"transport"`` — connection refused, DNS, timeout, etc.
- ``"json"``   — server returned non-JSON.
- ``"guard"``  — local guard (e.g. bearer token refused for non-local URL).
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from typing import Any, Optional
from urllib.parse import urlparse

from . import credentials

DEFAULT_URL = "http://localhost:3100"

_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})


class PaperclipAPIError(Exception):
    """Structured error raised by :class:`PaperclipAPI`."""

    def __init__(
        self,
        message: str,
        *,
        kind: str,
        status: Optional[int] = None,
        method: str = "",
        path: str = "",
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.status = status
        self.method = method
        self.path = path


def _log_error(method: str, path: str, exc: BaseException) -> None:
    # Never leak full URL (which could embed inline credentials in a
    # pathological config); ``path`` is already the request path.
    print(
        f"[paperclip-api] {type(exc).__name__} on {method} {path}: {exc}",
        file=sys.stderr,
    )


class PaperclipAPI:
    def __init__(self, url: str = DEFAULT_URL, token_env_key: Optional[str] = None) -> None:
        self.url = url.rstrip("/")
        self.token_env_key = token_env_key

    def _is_local(self) -> bool:
        """True only for loopback hosts — gate for bearer-token attachment."""
        host = (urlparse(self.url).hostname or "").lower()
        return host in _LOCAL_HOSTS

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.token_env_key and self._is_local():
            token = credentials.get(self.token_env_key)
            if token:
                h["Authorization"] = f"Bearer {token}"
        return h

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[dict] = None,
        timeout: float = 10.0,
    ) -> Any:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            f"{self.url}{path}",
            data=data,
            method=method,
            headers=self._headers(),
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                raw = resp.read()
                if not raw:
                    return {}
                return json.loads(raw.decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            _log_error(method, path, exc)
            raise PaperclipAPIError(
                f"HTTP {exc.code}: {exc.reason}",
                kind="http", status=exc.code, method=method, path=path,
            ) from exc
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            _log_error(method, path, exc)
            raise PaperclipAPIError(
                "transport error",
                kind="transport", method=method, path=path,
            ) from exc
        except json.JSONDecodeError as exc:
            _log_error(method, path, exc)
            raise PaperclipAPIError(
                "bad JSON response",
                kind="json", method=method, path=path,
            ) from exc

    # ------------------------------------------------------------------
    # Soft-fail helpers — callers that explicitly want None on failure.
    # ------------------------------------------------------------------

    def health(self) -> bool:
        try:
            body = self._request("GET", "/api/health", timeout=3.0)
        except PaperclipAPIError:
            return False
        return isinstance(body, dict) and body.get("status") in ("ok", "up", "healthy")

    def list_companies(self) -> list[dict]:
        try:
            body = self._request("GET", "/api/companies")
        except PaperclipAPIError:
            return []
        return body if isinstance(body, list) else []

    def create_company(self, slug: str, name: str) -> dict:
        """Create a company. Raises :class:`PaperclipAPIError` on failure."""
        result = self._request(
            "POST", "/api/companies", {"slug": slug, "name": name},
        )
        if not isinstance(result, dict):
            raise PaperclipAPIError(
                f"create_company returned non-object: {type(result).__name__}",
                kind="json", method="POST", path="/api/companies",
            )
        return result

    def create_company_soft(self, slug: str, name: str) -> Optional[dict]:
        """Soft-fail variant: ``None`` on any API error."""
        try:
            return self.create_company(slug, name)
        except PaperclipAPIError:
            return None

    def list_agents(self, company_id: str) -> list[dict]:
        try:
            body = self._request("GET", f"/api/companies/{company_id}/agents")
        except PaperclipAPIError:
            return []
        return body if isinstance(body, list) else []

    def create_agent(
        self,
        company_id: str,
        name: str,
        backend_config: dict,
        system_prompt: str,
    ) -> dict:
        """Create a Paperclip agent. Raises :class:`PaperclipAPIError` on
        failure. Callers that want soft-fail use :meth:`create_agent_soft`.

        Returning ``None`` here is a footgun: provisioning would persist an
        agent record with ``paperclip_agent_id=None`` and silently swallow
        every task ever assigned to it.
        """
        payload = {
            "name": name,
            "backend": backend_config,
            "systemPrompt": system_prompt,
        }
        result = self._request(
            "POST", f"/api/companies/{company_id}/agents", payload,
        )
        if not isinstance(result, dict):
            raise PaperclipAPIError(
                f"create_agent returned non-object: {type(result).__name__}",
                kind="json", method="POST",
                path=f"/api/companies/{company_id}/agents",
            )
        return result

    def create_agent_soft(
        self,
        company_id: str,
        name: str,
        backend_config: dict,
        system_prompt: str,
    ) -> Optional[dict]:
        """Soft-fail variant: ``None`` on any API error. Use only when the
        caller treats agent creation as opportunistic.
        """
        try:
            return self.create_agent(company_id, name, backend_config, system_prompt)
        except PaperclipAPIError:
            return None

    def find_agent_by_name(self, company_id: str, name: str) -> Optional[dict]:
        """Return the first agent with this exact ``name`` for the company, else ``None``."""
        for agent in self.list_agents(company_id):
            if isinstance(agent, dict) and agent.get("name") == name:
                return agent
        return None

    def upsert_agent(
        self,
        company_id: str,
        name: str,
        backend_config: dict,
        system_prompt: str,
    ) -> dict:
        """Return existing agent with this name, or create a new one.
        Idempotent. Raises :class:`PaperclipAPIError` on creation failure.
        """
        existing = self.find_agent_by_name(company_id, name)
        if existing is not None:
            return existing
        return self.create_agent(company_id, name, backend_config, system_prompt)

    def upsert_agent_soft(
        self,
        company_id: str,
        name: str,
        backend_config: dict,
        system_prompt: str,
    ) -> Optional[dict]:
        """Soft-fail variant of :meth:`upsert_agent`."""
        try:
            return self.upsert_agent(company_id, name, backend_config, system_prompt)
        except PaperclipAPIError:
            return None

    def delete_agent(self, company_id: str, agent_id: str) -> bool:
        try:
            self._request("DELETE", f"/api/companies/{company_id}/agents/{agent_id}")
            return True
        except PaperclipAPIError:
            return False

    def list_tasks(self, agent_id: str) -> list[dict]:
        try:
            body = self._request("GET", f"/api/agents/{agent_id}/tasks")
        except PaperclipAPIError:
            return []
        return body if isinstance(body, list) else []

    def create_task(self, agent_id: str, payload: dict) -> Optional[dict]:
        """Create a task. Returns ``None`` on failure (callers retry on next tick)."""
        try:
            return self._request("POST", f"/api/agents/{agent_id}/tasks", payload)
        except PaperclipAPIError:
            return None

    def create_task_strict(self, agent_id: str, payload: dict) -> dict:
        """Same as :meth:`create_task` but raises on failure for callers that
        need structured error info (e.g. ingest's skip-reason reporting).
        """
        return self._request("POST", f"/api/agents/{agent_id}/tasks", payload)

    def get_backup_dir(self) -> Optional[str]:
        try:
            body = self._request("GET", "/api/backup-location", timeout=3.0)
        except PaperclipAPIError:
            return None
        if isinstance(body, dict):
            return body.get("path") or body.get("dir")
        return None
