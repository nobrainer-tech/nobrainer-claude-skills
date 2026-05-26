"""CLI entry point.

Usage::

    python -m nobrainer_paperclip_setup                          # menu / onboarding
    python -m nobrainer_paperclip_setup detect [--json]
    python -m nobrainer_paperclip_setup companies {list,add}
    python -m nobrainer_paperclip_setup memory {install,status,uninstall}
    python -m nobrainer_paperclip_setup add-repo [--company SLUG] [REPO_PATH]
    python -m nobrainer_paperclip_setup scale COMPANY REPO DELTA
    python -m nobrainer_paperclip_setup status [--company SLUG] [--repo NAME] [--watch] [--json]
    python -m nobrainer_paperclip_setup verify COMPANY REPO [--fallback ...]
    python -m nobrainer_paperclip_setup teardown COMPANY REPO [--yes]
    python -m nobrainer_paperclip_setup health [--company SLUG] [--repo NAME]
    python -m nobrainer_paperclip_setup ingest [--company SLUG] [--json]
    python -m nobrainer_paperclip_setup reports [--company SLUG] [--repo NAME] [--open]
    python -m nobrainer_paperclip_setup relogin COMPANY REPO [--agent N]
    python -m nobrainer_paperclip_setup backups-gc [--retention-hours N] [--dry-run]
    python -m nobrainer_paperclip_setup install {opencode,paperclip} | install --check
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Callable


def _cmd_detect(args: argparse.Namespace) -> int:
    from . import detect
    snapshot = detect.detect_all()
    if args.json:
        json.dump(snapshot, sys.stdout, indent=2, sort_keys=True, default=str)
        sys.stdout.write("\n")
        return 0
    pc = snapshot["paperclip"]
    print(f"Paperclip:    {pc['url']} [{pc['status']}]  v{pc['version']}")
    print(f"Python:       {snapshot['python']}")
    print(f"Node / pnpm:  {snapshot['node']} / {snapshot['pnpm']}")
    print(f"Git:          {snapshot['git']}")
    print(f"Platform:     {snapshot['platform']}")
    be = snapshot["backends"]
    print(
        f"Backends:     codex={be['codex_cli']}  opencode={be['opencode']}  "
        f"gh_copilot={be['gh_copilot']}"
    )
    br = snapshot["browsers"]
    print(
        f"Browsers:     chrome={'yes' if br['chrome'] else 'no'}  "
        f"edge={'yes' if br['edge'] else 'no'}  brave={'yes' if br['brave'] else 'no'}"
    )
    cdp = snapshot["cdp_pool"]
    print(
        f"CDP pool:     {cdp['pool_start']}-{cdp['pool_end']} "
        f"({cdp['free_count']}/{cdp['pool_end'] - cdp['pool_start'] + 1} free)"
    )
    print(f"Onboarded:    {snapshot['onboarded']}")
    print(f"Companies:    {len(snapshot['companies'])}")
    for c in snapshot["companies"]:
        jira = "jira" if c.get("jira_enabled") else "no-jira"
        print(f"  - {c['slug']:<20} {c.get('display_name', '-'):<24} {jira}  repos={len(c.get('repos', []))}")
    print(f"Repos:        {len(snapshot['configured_repos'])}")
    for r in snapshot["configured_repos"]:
        print(f"  - {r['company']}/{r['repo']:<20} {r['agents']} agent(s)  ({r['framework']})")
    return 0


def _cmd_interactive(_args: argparse.Namespace) -> int:
    from . import interactive
    return interactive.run()


def _cmd_companies(args: argparse.Namespace) -> int:
    from .actions import companies as ac
    if args.action == "list":
        return ac.list_cmd(json_out=args.json)
    if args.action == "add":
        return ac.add_cmd()
    print(f"unknown companies action: {args.action}", file=sys.stderr)
    return 2


def _cmd_memory(args: argparse.Namespace) -> int:
    from .actions import memory as am
    if args.action == "install":
        return am.install(args.workspace)
    if args.action == "status":
        return am.status(json_out=args.json)
    if args.action == "uninstall":
        return am.uninstall()
    print(f"unknown memory action: {args.action}", file=sys.stderr)
    return 2


def _cmd_add_repo(args: argparse.Namespace) -> int:
    from .actions import add_repo
    return add_repo.run(repo_path=args.repo_path, company_slug=args.company, non_interactive=args.yes)


def _cmd_scale(args: argparse.Namespace) -> int:
    from .actions import scale
    return scale.run(company=args.company, repo=args.repo, delta=args.delta)


def _cmd_status(args: argparse.Namespace) -> int:
    from .actions import status
    return status.run(repo=args.repo, company=args.company, watch=args.watch, json_out=args.json)


def _cmd_verify(args: argparse.Namespace) -> int:
    from .actions import verify
    return verify.run(company=args.company, repo=args.repo, fallback=args.fallback)


def _cmd_teardown(args: argparse.Namespace) -> int:
    from .actions import teardown
    return teardown.run(company=args.company, repo=args.repo, yes=args.yes)


def _cmd_health(args: argparse.Namespace) -> int:
    from .actions import health
    return health.run(company=args.company, repo=args.repo)


def _cmd_ingest(args: argparse.Namespace) -> int:
    from .actions import ingest
    return ingest.run(
        company=args.company,
        json_out=args.json,
        force=args.force,
        strict=args.strict,
    )


def _cmd_reports(args: argparse.Namespace) -> int:
    from .actions import reports
    return reports.run(company=args.company, repo=args.repo, open_latest=args.open)


def _cmd_relogin(args: argparse.Namespace) -> int:
    from . import browser_pool
    return browser_pool.relogin(repo=args.repo, agent_id=args.agent, company=args.company)


def _cmd_install(args: argparse.Namespace) -> int:
    from . import npm_safe, opencode_install, paperclip_install

    if args.check:
        report = {
            "opencode": {
                "installed": opencode_install.is_installed(),
                "version": opencode_install.current_version(),
            },
            "paperclip": {
                "running": paperclip_install.is_running(),
            },
        }
        if args.json:
            json.dump(report, sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
        else:
            print(f"opencode installed: {report['opencode']['installed']}")
            print(f"opencode version:   {report['opencode']['version']}")
            print(f"paperclip running:  {report['paperclip']['running']}")
        return 0

    target = (args.target or "").strip().lower()
    if target == "opencode":
        try:
            result = opencode_install.install(cooldown_days=args.cooldown_days)
        except npm_safe.NpmSafeError as exc:
            print(f"[install] opencode failed: {exc}", file=sys.stderr)
            return 1
        if args.json:
            json.dump(result, sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
        else:
            print(
                f"opencode: resolved {result['package']}@{result['version']} "
                f"(age_days={result['age_days']}, rc={result['rc']})"
            )
            print(f"log: {result['log_path']}")
        if result["rc"] != 0:
            return result["rc"]
        check = opencode_install.verify()
        if not check["ok"]:
            print("[install] verify failed: opencode binary not callable", file=sys.stderr)
            return 1
        print(f"verified: {check['binary']} (v{check['version']})")
        return 0
    if target == "paperclip":
        if paperclip_install.is_running():
            print("paperclip already running on /api/health")
            return 0
        rc = paperclip_install.install_via_npx()
        if rc != 0:
            return rc
        if not paperclip_install.wait_for_alive(timeout=120):
            print("[install] paperclip did not become healthy within 120s", file=sys.stderr)
            return 1
        return 0
    print(
        f"install: target must be one of opencode|paperclip (got {target!r})",
        file=sys.stderr,
    )
    return 2


def _cmd_backups_gc(args: argparse.Namespace) -> int:
    from . import backups
    result = backups.gc(retention_hours=args.retention_hours, dry_run=args.dry_run)
    if args.json:
        json.dump(result, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
    else:
        print(
            f"deleted {len(result['deleted'])} file(s), "
            f"kept {len(result['kept'])}, "
            f"freed {result['total_bytes_freed']} bytes from {result['backup_dir']}"
        )
    # Exit 1 on partial failure (any per-file delete error) or refusal.
    if result.get("refused") or result.get("errors"):
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nobrainer-paperclip-setup",
        description="Cross-platform installer and orchestrator for Paperclip.",
        epilog="Run with no subcommand for the interactive menu / first-run onboarding.",
    )
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("detect", help="Print host state snapshot")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_detect)

    sp = sub.add_parser("companies", help="Company CRUD")
    sp.add_argument("action", choices=["list", "add"])
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_companies)

    sp = sub.add_parser("memory", help="Manage the nobrainer-memory skill")
    sp.add_argument("action", choices=["install", "status", "uninstall"])
    sp.add_argument("--workspace", default=None)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_memory)

    sp = sub.add_parser("add-repo", help="Attach a git repo to a company")
    sp.add_argument("repo_path", nargs="?", default=None)
    sp.add_argument("--company", default=None)
    sp.add_argument("--yes", action="store_true")
    sp.set_defaults(func=_cmd_add_repo)

    sp = sub.add_parser("scale", help="Add or remove agents for a configured repo")
    sp.add_argument("company")
    sp.add_argument("repo")
    sp.add_argument("delta", type=int, help="+N to add, -N to remove")
    sp.set_defaults(func=_cmd_scale)

    sp = sub.add_parser("status", help="Show agent dashboard")
    sp.add_argument("--company", default=None)
    sp.add_argument("--repo", default=None)
    sp.add_argument("--watch", action="store_true")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_status)

    sp = sub.add_parser("verify", help="Emit verification plan / run agent-browser fallback")
    sp.add_argument("company")
    sp.add_argument("repo")
    sp.add_argument(
        "--fallback",
        choices=["agent-browser", "manual"],
        default="agent-browser",
    )
    sp.set_defaults(func=_cmd_verify)

    sp = sub.add_parser("teardown", help="Remove company/repo from setup")
    sp.add_argument("company")
    sp.add_argument("repo")
    sp.add_argument("--yes", action="store_true")
    sp.set_defaults(func=_cmd_teardown)

    sp = sub.add_parser("health", help="Env URLs, scheduler, worktree fsck, browser sessions")
    sp.add_argument("--company", default=None)
    sp.add_argument("--repo", default=None)
    sp.set_defaults(func=_cmd_health)

    sp = sub.add_parser("ingest", help="Pull assigned Jira tickets and dispatch to agents")
    sp.add_argument("--company", default=None)
    sp.add_argument("--json", action="store_true")
    sp.add_argument(
        "--force", action="store_true",
        help="Bypass the working-hours gate for manual runs",
    )
    sp.add_argument(
        "--strict", action="store_true",
        help="Exit 1 if any company has skipped items",
    )
    sp.set_defaults(func=_cmd_ingest)

    sp = sub.add_parser("reports", help="List per-ticket reports")
    sp.add_argument("--company", default=None)
    sp.add_argument("--repo", default=None)
    sp.add_argument("--open", action="store_true")
    sp.set_defaults(func=_cmd_reports)

    sp = sub.add_parser("relogin", help="Open browser profile(s) for fresh login")
    sp.add_argument("company")
    sp.add_argument("repo")
    sp.add_argument("--agent", type=int, default=None)
    sp.set_defaults(func=_cmd_relogin)

    sp = sub.add_parser(
        "install",
        help="Install opencode / paperclip via the 7-day npm cooldown",
    )
    sp.add_argument(
        "target",
        nargs="?",
        default=None,
        help="opencode | paperclip (omit when using --check)",
    )
    sp.add_argument("--check", action="store_true", help="Report install status only")
    sp.add_argument("--cooldown-days", type=int, default=7)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_install)

    sp = sub.add_parser("backups-gc", help="Delete Paperclip backups older than retention")
    sp.add_argument("--retention-hours", type=int, default=48)
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_backups_gc)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    func: Callable[[argparse.Namespace], int] | None = getattr(args, "func", None)
    if func is None:
        return _cmd_interactive(args)
    try:
        return func(args)
    except KeyboardInterrupt:
        print("\n[nobrainer-paperclip-setup] aborted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
