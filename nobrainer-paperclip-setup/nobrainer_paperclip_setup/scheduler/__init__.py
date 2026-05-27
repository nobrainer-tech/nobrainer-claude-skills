"""OS-specific scheduler abstraction.

Picks the right backend based on ``sys.platform``:

- ``darwin`` → launchd (LaunchAgent under ``~/Library/LaunchAgents``)
- ``win32``  → Task Scheduler via ``schtasks.exe``
- otherwise  → systemd user units under ``~/.config/systemd/user``

All backends implement the same ``Scheduler`` interface defined in
``paperclip_setup.scheduler.base``.

Stub implementations are provided so the rest of the codebase can import and
``list_labels()`` safely; full install/remove logic lands in the backend files.
"""

from __future__ import annotations

import sys

from .base import Scheduler

_current: Scheduler | None = None


def current() -> Scheduler:
    """Return the singleton scheduler backend for this OS."""
    global _current
    if _current is not None:
        return _current

    if sys.platform == "darwin":
        from .launchd import LaunchdScheduler

        _current = LaunchdScheduler()
    elif sys.platform == "win32":
        from .task_scheduler import TaskSchedulerScheduler

        _current = TaskSchedulerScheduler()
    else:
        from .systemd_user import SystemdUserScheduler

        _current = SystemdUserScheduler()
    return _current
