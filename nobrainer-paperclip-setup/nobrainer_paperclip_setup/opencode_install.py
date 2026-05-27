"""Install the ``opencode`` CLI via the supply-chain-hardened npm wrapper.

The official npm package name is ``opencode-ai``. Installs always go through
:mod:`npm_safe`, so the resolved version is at least 7 days old.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from typing import Optional

from . import npm_safe

PACKAGE = "opencode-ai"
BIN_NAME = "opencode"


def is_installed() -> bool:
    """True iff the ``opencode`` binary resolves on the current PATH."""
    return shutil.which(BIN_NAME) is not None


def current_version() -> Optional[str]:
    """Return the installed ``opencode`` version string, or ``None``.

    Parses the first semver-looking token from ``opencode --version`` output.
    """
    binary = shutil.which(BIN_NAME)
    if binary is None:
        return None
    try:
        proc = subprocess.run(  # noqa: S603
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0:
        return None
    text = (proc.stdout or proc.stderr or "").strip()
    match = re.search(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-+]+)?", text)
    return match.group(0) if match else (text.splitlines()[0] if text else None)


def install(cooldown_days: int = 7) -> dict:
    """Install ``opencode-ai`` globally via :mod:`npm_safe`.

    Returns the dict produced by :func:`npm_safe.install_global`. Caller is
    responsible for inspecting ``rc`` and surfacing failures.
    """
    return npm_safe.install_global(PACKAGE, cooldown_days=cooldown_days)


def verify() -> dict:
    """Confirm the binary works after install.

    Returns ``{ok, version, binary}``. ``ok`` is False if the binary cannot
    be found or ``--version`` exits non-zero.
    """
    binary = shutil.which(BIN_NAME)
    if binary is None:
        return {"ok": False, "version": None, "binary": None}
    version = current_version()
    return {
        "ok": version is not None,
        "version": version,
        "binary": binary,
    }
