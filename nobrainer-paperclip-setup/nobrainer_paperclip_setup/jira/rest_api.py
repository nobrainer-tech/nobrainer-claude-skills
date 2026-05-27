"""Jira REST API v3 client. GET-only by design.

This module is intentionally restricted: only ``urllib.request.urlopen`` with
the default GET method is used. No POST/PUT/PATCH/DELETE calls exist anywhere
in this file. Reviewers should grep for ``method=`` or ``data=`` to confirm.
"""

from __future__ import annotations

import base64
import inspect
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional
from urllib.parse import urlparse

from .. import credentials
from .client import JiraClient

_FORBIDDEN_METHOD_PREFIXES = (
    "post_", "put_", "delete_", "patch_",
    "create_", "update_", "add_", "remove_",
)

_NON_GET_VERB_RE = re.compile(
    r"""(?ix)
    (?:method\s*=\s*['"](?:POST|PUT|DELETE|PATCH)['"])
    | (?:\.(?:post|put|delete|patch)\s*\()
    """
)


class JiraRestClient(JiraClient):
    backend_name = "rest-api"

    def __init__(
        self,
        server_url: str,
        email: Optional[str] = None,
        pat_env_key: Optional[str] = None,
    ) -> None:
        parsed = urlparse(server_url)
        if parsed.scheme != "https" and os.environ.get("JIRA_ALLOW_HTTP") != "1":
            raise ValueError(
                f"Jira server_url must use https://, got {server_url!r}. "
                "Set JIRA_ALLOW_HTTP=1 in your environment to override "
                "(NOT recommended)."
            )
        self.server_url = server_url.rstrip("/")
        self.email = email
        self.pat_env_key = pat_env_key
        self._verify_get_only()

    @classmethod
    def _verify_get_only(cls) -> None:
        """Best-effort runtime check: reject non-GET HTTP verbs in this class."""
        try:
            src = inspect.getsource(cls)
        except (OSError, TypeError):
            return
        if _NON_GET_VERB_RE.search(src):
            raise TypeError(
                f"{cls.__name__} must be GET-only; found non-GET HTTP verb "
                "in its source. This is a read-only Jira client."
            )

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        for attr in dir(cls):
            if attr.startswith(_FORBIDDEN_METHOD_PREFIXES):
                raise TypeError(
                    f"{cls.__name__}: subclasses of JiraRestClient must be "
                    f"GET-only; found method {attr!r}"
                )

    def _auth_header(self) -> dict[str, str]:
        if not self.pat_env_key:
            return {}
        token = credentials.get(self.pat_env_key)
        if not token:
            return {}
        if self.email:
            blob = f"{self.email}:{token}".encode("utf-8")
            return {"Authorization": "Basic " + base64.b64encode(blob).decode("ascii")}
        return {"Authorization": f"Bearer {token}"}

    def _get(self, path: str, params: Optional[dict] = None, timeout: float = 10.0) -> Optional[dict]:
        url = f"{self.server_url}{path}"
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        headers = {"Accept": "application/json"}
        headers.update(self._auth_header())
        req = urllib.request.Request(url, headers=headers)  # GET by default
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                raw = resp.read()
                return json.loads(raw.decode("utf-8", errors="replace")) if raw else {}
        except urllib.error.HTTPError as exc:
            # Log path only, never the full URL (avoids leaking inline creds).
            print(
                f"[jira-rest] HTTP {exc.code} on GET {path}: {exc.reason}",
                file=sys.stderr,
            )
            return None
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            print(
                f"[jira-rest] {type(exc).__name__} on GET {path}",
                file=sys.stderr,
            )
            return None
        except json.JSONDecodeError as exc:
            print(
                f"[jira-rest] {type(exc).__name__} on GET {path}: {exc}",
                file=sys.stderr,
            )
            return None

    def search_issues(self, jql: str, max_results: int = 50) -> list[dict]:
        body = self._get("/rest/api/3/search", {"jql": jql, "maxResults": max_results})
        if not body:
            return []
        return body.get("issues", []) or []

    def get_issue(self, key: str) -> Optional[dict]:
        return self._get(f"/rest/api/3/issue/{urllib.parse.quote(key)}")

    def get_current_user(self) -> Optional[dict]:
        return self._get("/rest/api/3/myself")
