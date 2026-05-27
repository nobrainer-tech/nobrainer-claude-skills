"""macOS launchd backend (LaunchAgent under ~/Library/LaunchAgents)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from string import Template

from .. import paths
from .base import Scheduler, ScheduleSpec

AGENTS_DIR = Path.home() / "Library" / "LaunchAgents"


def _xml_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


class LaunchdScheduler(Scheduler):
    name = "launchd"

    def install(self, spec: ScheduleSpec) -> None:
        AGENTS_DIR.mkdir(parents=True, exist_ok=True)
        if spec.interval_seconds is not None and spec.keep_alive:
            raise ValueError("interval_seconds and keep_alive are mutually exclusive")

        tmpl_path = paths.templates_dir() / "scheduler" / "launchd.plist.tmpl"
        template = Template(tmpl_path.read_text(encoding="utf-8"))

        program_args = "".join(
            f"        <string>{_xml_escape(str(arg))}</string>\n" for arg in spec.command
        )

        if spec.interval_seconds is not None:
            schedule_block = (
                f"    <key>StartInterval</key>\n"
                f"    <integer>{int(spec.interval_seconds)}</integer>\n"
                f"    <key>RunAtLoad</key>\n    <true/>\n"
            )
        elif spec.keep_alive:
            schedule_block = (
                "    <key>KeepAlive</key>\n    <true/>\n"
                "    <key>RunAtLoad</key>\n    <true/>\n"
            )
        else:
            schedule_block = "    <key>RunAtLoad</key>\n    <true/>\n"

        if spec.working_directory:
            working_directory_block = (
                f"    <key>WorkingDirectory</key>\n"
                f"    <string>{_xml_escape(str(spec.working_directory))}</string>\n"
            )
        else:
            working_directory_block = ""

        if spec.environment:
            env_items = "".join(
                f"        <key>{_xml_escape(k)}</key>\n        <string>{_xml_escape(v)}</string>\n"
                for k, v in spec.environment.items()
            )
            environment_block = (
                f"    <key>EnvironmentVariables</key>\n    <dict>\n{env_items}    </dict>\n"
            )
        else:
            environment_block = ""

        stdout_log = spec.stdout_log or (paths.logs_dir() / f"{spec.label}.out.log")
        stderr_log = spec.stderr_log or (paths.logs_dir() / f"{spec.label}.err.log")
        stdout_log.parent.mkdir(parents=True, exist_ok=True)
        stderr_log.parent.mkdir(parents=True, exist_ok=True)

        plist_text = template.substitute(
            label=_xml_escape(spec.label),
            program_arguments=program_args,
            schedule_block=schedule_block,
            working_directory_block=working_directory_block,
            environment_block=environment_block,
            stdout_log=_xml_escape(str(stdout_log)),
            stderr_log=_xml_escape(str(stderr_log)),
        )

        plist_path = AGENTS_DIR / f"{spec.label}.plist"
        paths.atomic_write_text(plist_path, plist_text)

        subprocess.run(
            ["launchctl", "unload", str(plist_path)],
            capture_output=True, check=False,
        )
        subprocess.run(
            ["launchctl", "load", "-w", str(plist_path)],
            capture_output=True, check=False,
        )

    def remove(self, label: str) -> bool:
        plist = AGENTS_DIR / f"{label}.plist"
        if not plist.exists():
            return False
        subprocess.run(
            ["launchctl", "unload", str(plist)],
            check=False, capture_output=True,
        )
        plist.unlink()
        return True

    def list_labels(self, prefix: str | None = None) -> list[str]:
        try:
            out = subprocess.run(
                ["launchctl", "list"], capture_output=True, text=True,
                timeout=5, check=False,
            ).stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []
        labels: list[str] = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 3:
                continue
            label = parts[2]
            if prefix is None or label.startswith(prefix):
                labels.append(label)
        return labels
