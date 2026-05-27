"""``reports`` action: list generated reports; optionally open the latest."""

from __future__ import annotations

import sys
import webbrowser
from pathlib import Path
from typing import Optional

from .. import paths, state as state_mod


def _find_reports(company: Optional[str], repo: Optional[str]) -> list[Path]:
    out: list[Path] = []
    for s in state_mod.list_all():
        if company and s.get("company") != company:
            continue
        if repo and s.get("repo") != repo:
            continue
        root = paths.tickets_dir(s["company"], s["repo"])
        out.extend(sorted(root.glob("*/report.html")))
    return out


def run(company: Optional[str] = None, repo: Optional[str] = None, open_latest: bool = False) -> int:
    reports = _find_reports(company, repo)
    if not reports:
        print("(no reports yet)")
        return 0

    for p in reports:
        mtime = p.stat().st_mtime
        print(f"  {p}  (mtime={int(mtime)})")

    if open_latest:
        latest = max(reports, key=lambda p: p.stat().st_mtime)
        url = latest.resolve().as_uri()
        try:
            webbrowser.open(url)
        except Exception as exc:  # noqa: BLE001
            print(f"could not open browser: {exc}", file=sys.stderr)
            return 1
        print(f"opened: {url}")
    return 0
