"""``ingest`` action: run a Jira poll for one company or all."""

from __future__ import annotations

import json
import sys
from typing import Optional

from .. import companies
from ..tickets import ingest as ingest_mod


def run(
    company: Optional[str] = None,
    json_out: bool = False,
    force: bool = False,
    strict: bool = False,
) -> int:
    if company:
        results = [ingest_mod.ingest_for_company(company, force=force)]
    else:
        results = ingest_mod.ingest_all(force=force)

    if not results:
        print("(no companies to ingest)")
        return 0

    if json_out:
        json.dump(results, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
        # Exit code in JSON mode mirrors text mode so CI can rely on it.
        return _compute_exit_code(results, strict=strict)

    failed = 0
    skipped_total = 0
    for r in results:
        if not r.get("ok"):
            failed += 1
            print(f"FAIL {r.get('company')}: {r.get('reason')}", file=sys.stderr)
            continue
        skipped = r.get("skipped", []) or []
        skipped_total += len(skipped)
        print(
            f"OK   {r.get('company')}: {len(r.get('dispatched', []))} dispatched, "
            f"{len(skipped)} skipped, {r.get('issues_seen')} seen"
        )
    _list_known(json_out)
    return _compute_exit_code(results, strict=strict, failed=failed)


def _compute_exit_code(
    results: list[dict],
    *,
    strict: bool,
    failed: Optional[int] = None,
) -> int:
    """Exit 1 if any company hard-failed; in strict mode any skipped item fails."""
    if failed is None:
        failed = sum(1 for r in results if not r.get("ok"))
    if failed > 0:
        return 1
    if strict and any((r.get("skipped") or []) for r in results):
        return 1
    return 0


def _list_known(json_out: bool) -> None:
    if json_out:
        return
    items = companies.list_companies()
    if not items:
        return
    enabled = [c for c in items if (c.get("jira") or {}).get("enabled")]
    if enabled:
        return
    print("(no companies have Jira enabled; nothing to ingest)")
