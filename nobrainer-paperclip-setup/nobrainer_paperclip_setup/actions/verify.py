"""``verify`` action: emit a verification plan or run the agent-browser fallback."""

from __future__ import annotations

import sys
from typing import Optional

from .. import paths, state as state_mod, verify as verify_mod


def run(company: str, repo: str, fallback: Optional[str] = "agent-browser") -> int:
    st = state_mod.load(company, repo)
    if not st:
        print(f"no state for {company}/{repo}", file=sys.stderr)
        return 1

    ts = paths.now_utc_compact()
    out_dir = paths.company_log_dir(company, repo) / f"verify-{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)
    plan_path = out_dir / "plan.md"
    plan_path.write_text(verify_mod.verification_plan(st), encoding="utf-8")
    print(f"verification plan written: {plan_path}")

    if fallback == "agent-browser":
        result = verify_mod.run_via_agent_browser(st)
        summary = verify_mod.summarize_results(result)
        (out_dir / "fallback-result.txt").write_text(summary, encoding="utf-8")
        print(f"agent-browser fallback: {summary}")
        return 0 if result.get("ok") else 1

    print(
        "manual fallback: open the plan above and execute each step in your "
        "preferred browser; write PASS/FAIL into the same directory."
    )
    return 0
