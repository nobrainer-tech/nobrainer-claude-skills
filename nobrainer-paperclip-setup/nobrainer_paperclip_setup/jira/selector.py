"""Pick the right Jira backend for a given company."""

from __future__ import annotations

from typing import Any, Optional

from .. import credentials
from .atlassian_mcp import AtlassianMCPClient
from .client import JiraClient
from .rest_api import JiraRestClient


def get_client(company: dict[str, Any]) -> Optional[JiraClient]:
    jira_cfg = company.get("jira") or {}
    if not jira_cfg.get("enabled"):
        return None
    backend = (jira_cfg.get("backend") or "none").lower()
    server_url = jira_cfg.get("server_url") or ""
    slug = company.get("slug", "default")

    if backend == "atlassian-mcp":
        return AtlassianMCPClient(company=slug, server_url=server_url)
    if backend == "rest-api":
        return JiraRestClient(
            server_url=server_url,
            email=jira_cfg.get("email"),
            pat_env_key=credentials.company_jira_pat_key(slug),
        )
    return None
