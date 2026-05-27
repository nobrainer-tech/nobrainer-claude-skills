"""Read-only Jira backends.

All clients in this package MUST be read-only — no POST, PUT, PATCH, DELETE
methods are permitted anywhere in this subpackage.
"""

from .selector import get_client

__all__ = ["get_client"]
