"""Abstract scheduler interface.

All OS backends in this package implement these methods. The full schedule
spec is intentionally minimal — we only need:

- run a command on a fixed interval
- run a command at startup, kept alive on crash
- list / remove our own scheduled tasks (filtered by label prefix)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence


# Strict label charset: leading alnum, then alnum/dot/underscore/dash.
# Length cap at 200 chars satisfies Windows TaskScheduler (240 incl. namespace).
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")


@dataclass
class ScheduleSpec:
    label: str
    """Globally unique identifier, e.g. ``dev.paperclipsetup.my-repo.env-watcher``."""

    command: Sequence[str]
    """Argv to execute. Absolute paths recommended for portability."""

    working_directory: Path | None = None

    interval_seconds: int | None = None
    """If set, run on this interval. Mutually exclusive with ``keep_alive``."""

    keep_alive: bool = False
    """If True, run on load and restart on crash (no fixed interval)."""

    environment: dict[str, str] = field(default_factory=dict)

    stdout_log: Path | None = None
    stderr_log: Path | None = None

    def __post_init__(self) -> None:
        if not _LABEL_RE.match(self.label or ""):
            raise ValueError(
                f"invalid scheduler label: {self.label!r}. "
                "Allowed: [A-Za-z0-9][A-Za-z0-9._-]{0,199}"
            )


class Scheduler:
    name: str = "base"

    def install(self, spec: ScheduleSpec) -> None:
        raise NotImplementedError

    def remove(self, label: str) -> bool:
        """Return True if a task was removed."""
        raise NotImplementedError

    def list_labels(self, prefix: str | None = None) -> list[str]:
        raise NotImplementedError

    def is_installed(self, label: str) -> bool:
        return label in self.list_labels()
