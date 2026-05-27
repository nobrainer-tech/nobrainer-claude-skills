"""Linux systemd --user backend."""

from __future__ import annotations

import shlex
import subprocess
from pathlib import Path
from string import Template

from .. import paths
from .base import Scheduler, ScheduleSpec

UNIT_DIR = Path.home() / ".config" / "systemd" / "user"


class SystemdUserScheduler(Scheduler):
    name = "systemd_user"

    def install(self, spec: ScheduleSpec) -> None:
        if spec.interval_seconds is not None and spec.keep_alive:
            raise ValueError("interval_seconds and keep_alive are mutually exclusive")

        UNIT_DIR.mkdir(parents=True, exist_ok=True)

        service_tmpl = Template(
            (paths.templates_dir() / "scheduler" / "systemd.service.tmpl").read_text(encoding="utf-8")
        )
        timer_tmpl = Template(
            (paths.templates_dir() / "scheduler" / "systemd.timer.tmpl").read_text(encoding="utf-8")
        )

        exec_start = " ".join(shlex.quote(str(c)) for c in spec.command)
        working_directory = str(spec.working_directory or Path.home())
        env_lines = "".join(
            f'Environment="{k}={v}"\n' for k, v in spec.environment.items()
        )
        restart_block = "Restart=always\nRestartSec=5\n" if spec.keep_alive else ""

        stdout_log = spec.stdout_log or (paths.logs_dir() / f"{spec.label}.out.log")
        stderr_log = spec.stderr_log or (paths.logs_dir() / f"{spec.label}.err.log")
        stdout_log.parent.mkdir(parents=True, exist_ok=True)
        stderr_log.parent.mkdir(parents=True, exist_ok=True)

        service_text = service_tmpl.substitute(
            description=spec.label,
            exec_start=exec_start,
            working_directory=working_directory,
            environment_lines=env_lines,
            restart_block=restart_block,
            stdout_log=str(stdout_log),
            stderr_log=str(stderr_log),
        )

        service_path = UNIT_DIR / f"{spec.label}.service"
        paths.atomic_write_text(service_path, service_text)

        subprocess.run(
            ["systemctl", "--user", "daemon-reload"],
            capture_output=True, check=False,
        )

        if spec.interval_seconds is not None:
            timer_text = timer_tmpl.substitute(
                description=spec.label,
                interval_seconds=int(spec.interval_seconds),
                service_unit=f"{spec.label}.service",
            )
            timer_path = UNIT_DIR / f"{spec.label}.timer"
            paths.atomic_write_text(timer_path, timer_text)
            subprocess.run(
                ["systemctl", "--user", "daemon-reload"],
                capture_output=True, check=False,
            )
            subprocess.run(
                ["systemctl", "--user", "enable", "--now", f"{spec.label}.timer"],
                capture_output=True, check=False,
            )
        else:
            subprocess.run(
                ["systemctl", "--user", "enable", "--now", f"{spec.label}.service"],
                capture_output=True, check=False,
            )

    def remove(self, label: str) -> bool:
        unit_service = UNIT_DIR / f"{label}.service"
        unit_timer = UNIT_DIR / f"{label}.timer"
        removed = False
        for unit in (unit_timer, unit_service):
            if unit.exists():
                subprocess.run(
                    ["systemctl", "--user", "disable", "--now", unit.name],
                    capture_output=True, check=False,
                )
                unit.unlink()
                removed = True
        if removed:
            subprocess.run(
                ["systemctl", "--user", "daemon-reload"],
                capture_output=True, check=False,
            )
        return removed

    def list_labels(self, prefix: str | None = None) -> list[str]:
        if not UNIT_DIR.exists():
            return []
        labels: list[str] = []
        for unit in UNIT_DIR.glob("*.service"):
            label = unit.stem
            if prefix is None or label.startswith(prefix):
                labels.append(label)
        return labels
