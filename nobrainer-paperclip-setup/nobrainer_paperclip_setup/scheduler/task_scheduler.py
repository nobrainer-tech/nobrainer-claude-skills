"""Windows Task Scheduler backend via ``schtasks.exe``.

Notes:
- Windows TS has no native KeepAlive; we wrap the command in a small PowerShell
  ``while ($true) { & cmd args ; Start-Sleep 5 }`` loop and register that as a
  one-shot at logon. The wrapper script is regenerated on every install.
- Interval scheduling uses ``/SC MINUTE /MO N`` where N = ceil(interval / 60).
- All dynamic data (paths, env values, argv) is passed via ``-EncodedCommand``
  (UTF-16-LE base64). PowerShell never parses our strings — eliminates the
  entire class of quoting/injection bugs against `;`, `&`, `|`, `` ` ``, `$()`.
"""

from __future__ import annotations

import base64
import math
import re
import subprocess
from pathlib import Path

from .. import paths
from .base import Scheduler, ScheduleSpec


# PowerShell env var names: must start with letter/underscore, alnum + underscore.
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _ps_quote(value: str) -> str:
    """Single-quote a PowerShell literal (escapes embedded single quotes)."""
    return "'" + str(value).replace("'", "''") + "'"


def _validate_env(env: dict[str, str]) -> None:
    for k in env or {}:
        if not _ENV_NAME_RE.match(k):
            raise ValueError(f"invalid env var name: {k!r}")


def _encode_powershell(script: str) -> str:
    """Encode a PowerShell script for ``-EncodedCommand`` (UTF-16-LE + base64)."""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def _build_powershell_script(spec: ScheduleSpec, keep_alive: bool) -> str:
    """Compose the full PowerShell script as a string.

    All interpolated values are inside ``_ps_quote`` literals; control flow
    keywords are static. The wrapper is then base64-encoded so PowerShell never
    parses the user-controlled fragments at all.
    """
    _validate_env(spec.environment)
    lines: list[str] = ["$ErrorActionPreference = 'Continue'"]
    for k, v in (spec.environment or {}).items():
        lines.append(f"$env:{k} = {_ps_quote(v)}")
    if spec.working_directory:
        lines.append(f"Set-Location -Path {_ps_quote(str(spec.working_directory))}")
    if spec.stdout_log:
        spec.stdout_log.parent.mkdir(parents=True, exist_ok=True)
    if spec.stderr_log:
        spec.stderr_log.parent.mkdir(parents=True, exist_ok=True)

    head = _ps_quote(str(spec.command[0]))
    cmd_argv = ", ".join(_ps_quote(str(c)) for c in spec.command[1:])
    args_part = f" {cmd_argv}" if cmd_argv else ""

    redirect = ""
    if spec.stdout_log and spec.stderr_log:
        redirect = (
            f" *>> {_ps_quote(str(spec.stdout_log))}"
            f" 2>> {_ps_quote(str(spec.stderr_log))}"
        )

    invocation = f"& {head}{args_part}{redirect}"

    if keep_alive:
        lines.append("while ($true) {")
        lines.append(f"  {invocation}")
        lines.append("  Start-Sleep -Seconds 5")
        lines.append("}")
    else:
        lines.append(invocation)
    return "\n".join(lines)


class TaskSchedulerScheduler(Scheduler):
    name = "task_scheduler"

    def install(self, spec: ScheduleSpec) -> None:
        if spec.interval_seconds is not None and spec.keep_alive:
            raise ValueError("interval_seconds and keep_alive are mutually exclusive")
        _validate_env(spec.environment)

        subprocess.run(
            ["schtasks", "/Delete", "/TN", spec.label, "/F"],
            capture_output=True, check=False,
        )

        script = _build_powershell_script(spec, keep_alive=spec.keep_alive)
        encoded = _encode_powershell(script)
        # /TR is a single string; PowerShell flags + base64 blob are all static
        # ASCII so there is nothing for cmd.exe to misparse.
        tr_value = (
            f'powershell.exe -NoProfile -NonInteractive '
            f'-ExecutionPolicy Bypass -EncodedCommand {encoded}'
        )

        if spec.keep_alive:
            args = [
                "schtasks", "/Create",
                "/TN", spec.label,
                "/TR", tr_value,
                "/SC", "ONLOGON",
                "/RL", "LIMITED",
                "/F",
            ]
        elif spec.interval_seconds is not None:
            minutes = max(1, math.ceil(spec.interval_seconds / 60))
            args = [
                "schtasks", "/Create",
                "/TN", spec.label,
                "/TR", tr_value,
                "/SC", "MINUTE",
                "/MO", str(minutes),
                "/F",
            ]
        else:
            args = [
                "schtasks", "/Create",
                "/TN", spec.label,
                "/TR", tr_value,
                "/SC", "ONLOGON",
                "/F",
            ]

        subprocess.run(args, capture_output=True, check=False)

    def remove(self, label: str) -> bool:
        try:
            res = subprocess.run(
                ["schtasks", "/Delete", "/TN", label, "/F"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            return res.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def list_labels(self, prefix: str | None = None) -> list[str]:
        try:
            out = subprocess.run(
                ["schtasks", "/Query", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=10, check=False,
            ).stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []
        labels: list[str] = []
        for line in out.splitlines():
            if not line.strip():
                continue
            name = line.split(",", 1)[0].strip().strip('"')
            normalized = name.lstrip("\\")
            if prefix is None or normalized.startswith(prefix):
                labels.append(normalized)
        return labels
