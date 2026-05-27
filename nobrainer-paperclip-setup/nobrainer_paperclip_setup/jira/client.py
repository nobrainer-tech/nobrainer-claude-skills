"""Abstract Jira client — read-only interface only."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional


class JiraClient(ABC):
    backend_name: str = "abstract"

    @abstractmethod
    def search_issues(self, jql: str, max_results: int = 50) -> list[dict]:
        ...

    @abstractmethod
    def get_issue(self, key: str) -> Optional[dict]:
        ...

    @abstractmethod
    def get_current_user(self) -> Optional[dict]:
        ...
