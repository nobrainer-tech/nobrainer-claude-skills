"""``memory`` subcommand: install / status / uninstall nobrainer-memory."""

from __future__ import annotations

import json
import sys

from .. import memory as memory_mod


def install(workspace: str | None = None) -> int:
    from pathlib import Path
    ws = Path(workspace).expanduser() if workspace else memory_mod.detect_workspace()
    return memory_mod.install_memory(ws)


def status(json_out: bool = False) -> int:
    s = memory_mod.status()
    if json_out:
        json.dump(s, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
    else:
        print(f"workspace: {s['workspace']}")
        print(f"installed: {s['installed']}")
        print(f"preferences: {s['preferences_snapshot']}")
    return 0


def uninstall() -> int:
    return memory_mod.uninstall_memory()
