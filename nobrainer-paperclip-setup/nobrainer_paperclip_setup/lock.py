"""Cross-platform exclusive file lock for serializing port/state allocation.

Uses ``fcntl.flock`` on POSIX and ``msvcrt.locking`` on Windows. The platform
module is imported lazily inside the context manager so this file imports
cleanly on both platforms. Both code paths enforce ``timeout`` via a
non-blocking acquire + sleep loop; raises :class:`TimeoutError` on expiry.
"""

from __future__ import annotations

import contextlib
import sys
import time
from typing import Iterator

from . import paths

_POLL_INTERVAL_S = 0.05


@contextlib.contextmanager
def exclusive(name: str, timeout: float = 30.0) -> Iterator[None]:
    """Acquire an exclusive cross-platform file lock named ``name``.

    ``timeout`` is enforced on both platforms via non-blocking acquire + retry.
    Raises :class:`TimeoutError` if the lock is not acquired in time. Lock
    files live under ``config_dir``.
    """
    lock_path = paths.config_dir() / f"{name}.lock"
    lock_path.touch(exist_ok=True)
    deadline = time.monotonic() + max(timeout, 0.0)

    if sys.platform == "win32":
        import msvcrt  # type: ignore[import-not-found]

        fh = open(lock_path, "r+")
        try:
            while True:
                try:
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(
                            f"could not acquire lock {name!r} within {timeout}s"
                        )
                    time.sleep(_POLL_INTERVAL_S)
            try:
                yield
            finally:
                try:
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
        finally:
            fh.close()
    else:
        import fcntl  # type: ignore[import-not-found]

        fh = open(lock_path, "r+")
        try:
            while True:
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(
                            f"could not acquire lock {name!r} within {timeout}s"
                        )
                    time.sleep(_POLL_INTERVAL_S)
            try:
                yield
            finally:
                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
        finally:
            fh.close()
