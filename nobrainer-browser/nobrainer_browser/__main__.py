"""CLI entry point for ``python -m nobrainer_browser``.

Subcommands:
  detect, install, wire, unwire, verify, status
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from . import __version__, detect, npm_safe, paths, verify
from .tools import agent_browser as t_ab
from .tools import playwright_cli as t_pc
from .tools import playwright_mcp as t_pm
from .tools import webwright as t_ww
from .wire import claude as w_claude
from .wire import codex as w_codex

TOOL_KEYS = ("webwright", "playwright-mcp", "playwright-cli", "agent-browser")


def _print_json(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True, default=str))


def _emit(result: Any, json_out: bool) -> int:
    if json_out:
        _print_json(result)
    else:
        _print_json(result)
    if isinstance(result, dict) and result.get("ok") is False:
        return 1
    return 0


# ---------------------------------------------------------------------------
# install
# ---------------------------------------------------------------------------


def _install_one(tool: str, *, cooldown_days: int, dry_run: bool,
                 method: str = "npm", with_deps: bool = False,
                 webwright_mode: str = "marketplace",
                 webwright_hosts: list[str] | None = None) -> dict:
    if tool == "webwright":
        return t_ww.install(
            mode=webwright_mode,
            hosts=webwright_hosts,
            cooldown_days=cooldown_days,
            dry_run=dry_run,
        )
    if tool == "playwright-mcp":
        return t_pm.install(cooldown_days=cooldown_days, dry_run=dry_run)
    if tool == "playwright-cli":
        return t_pc.install(cooldown_days=cooldown_days, dry_run=dry_run, with_deps=with_deps)
    if tool == "agent-browser":
        return t_ab.install(cooldown_days=cooldown_days, dry_run=dry_run,
                            method=method, with_deps=with_deps)
    return {"tool": tool, "ok": False, "error": f"unknown tool: {tool}"}


def _parse_hosts_csv(value: str | None) -> tuple[list[str] | None, str | None]:
    """Parse a ``--hosts`` CSV. Returns (hosts, error_msg)."""
    if value is None:
        return None, None
    parts = [p.strip().lower() for p in value.split(",") if p.strip()]
    if not parts:
        return None, "empty --hosts list"
    invalid = [p for p in parts if p not in t_ww.VALID_HOSTS]
    if invalid:
        return None, f"invalid host(s): {invalid} (valid: {list(t_ww.VALID_HOSTS)})"
    # dedupe while preserving order
    seen: set[str] = set()
    out: list[str] = []
    for p in parts:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out, None


def _cmd_install(args: argparse.Namespace) -> int:
    target = args.target
    cooldown = args.cooldown_days
    webwright_hosts, host_err = _parse_hosts_csv(getattr(args, "hosts", None))
    if host_err:
        print(host_err, file=sys.stderr)
        return 2
    webwright_mode = getattr(args, "mode", "marketplace")
    if target == "all":
        results = []
        ok = True
        for t in TOOL_KEYS:
            method = args.method if t == "agent-browser" else "npm"
            res = _install_one(
                t, cooldown_days=cooldown, dry_run=args.dry_run,
                method=method, with_deps=args.with_deps,
                webwright_mode=webwright_mode,
                webwright_hosts=webwright_hosts,
            )
            results.append(res)
            ok = ok and bool(res.get("ok"))
        out = {"ok": ok, "results": results}
        _print_json(out)
        return 0 if ok else 1

    if target not in TOOL_KEYS:
        print(f"unknown install target: {target}", file=sys.stderr)
        return 2
    res = _install_one(
        target, cooldown_days=cooldown, dry_run=args.dry_run,
        method=args.method, with_deps=args.with_deps,
        webwright_mode=webwright_mode,
        webwright_hosts=webwright_hosts,
    )
    return _emit(res, json_out=True)


def _cmd_uninstall(args: argparse.Namespace) -> int:
    if args.target != "webwright":
        print(f"only 'webwright' is uninstallable today (got: {args.target})",
              file=sys.stderr)
        return 2
    hosts, err = _parse_hosts_csv(getattr(args, "hosts", None))
    if err:
        print(err, file=sys.stderr)
        return 2
    res = t_ww.uninstall(hosts=hosts, keep_source=not args.purge_source)
    return _emit(res, json_out=True)


# ---------------------------------------------------------------------------
# wire / unwire
# ---------------------------------------------------------------------------


def _resolve_pin(cooldown_days: int) -> str:
    """Return the cached safe version, resolving it if missing."""
    state = paths.load_json(paths.state_file()) or {}
    pin = state.get("playwright_mcp_version") if isinstance(state, dict) else None
    if pin:
        return str(pin)
    # Resolve on the fly.
    version = npm_safe.resolve_safe_version("@playwright/mcp", cooldown_days=cooldown_days)
    if not isinstance(state, dict):
        state = {}
    state["playwright_mcp_version"] = version
    state["playwright_mcp_resolved_at"] = paths.now_utc_iso()
    paths.atomic_write_json(paths.state_file(), state)
    return version


def _cmd_wire(args: argparse.Namespace) -> int:
    if args.tool != "playwright-mcp":
        print(f"only 'playwright-mcp' is wireable today (got: {args.tool})", file=sys.stderr)
        return 2
    try:
        pin = _resolve_pin(args.cooldown_days)
    except npm_safe.NpmSafeError as exc:
        print(f"failed to resolve safe version: {exc}", file=sys.stderr)
        return 1

    targets = ["claude", "codex"] if args.target == "both" else [args.target]
    results: dict[str, Any] = {"safe_version": pin, "targets": {}}
    overall_ok = True
    for t in targets:
        if t == "claude":
            r = w_claude.wire_playwright_mcp(pin)
        elif t == "codex":
            r = w_codex.wire_playwright_mcp(pin)
        else:
            r = {"ok": False, "error": f"unknown target: {t}"}
            overall_ok = False
        results["targets"][t] = r
        if r.get("rc", 0) != 0 and not r.get("method"):
            overall_ok = False
    results["ok"] = overall_ok
    _print_json(results)
    return 0 if overall_ok else 1


def _cmd_unwire(args: argparse.Namespace) -> int:
    if args.tool != "playwright-mcp":
        print(f"only 'playwright-mcp' is unwireable today (got: {args.tool})", file=sys.stderr)
        return 2
    targets = ["claude", "codex"] if args.target == "both" else [args.target]
    results: dict[str, Any] = {"targets": {}}
    for t in targets:
        if t == "claude":
            results["targets"][t] = w_claude.unwire_playwright_mcp()
        elif t == "codex":
            results["targets"][t] = w_codex.unwire_playwright_mcp()
        else:
            results["targets"][t] = {"ok": False, "error": f"unknown target: {t}"}
    results["ok"] = True
    _print_json(results)
    return 0


# ---------------------------------------------------------------------------
# detect / verify / status
# ---------------------------------------------------------------------------


def _cmd_detect(args: argparse.Namespace) -> int:
    data = detect.detect_all()
    _print_json(data)
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    tools = args.tool or None
    if tools and len(tools) == 1 and tools[0] == "all":
        tools = None
    data = verify.verify_all(tools)
    _print_json(data)
    return 0 if data.get("ok") else 1


def _cmd_status(args: argparse.Namespace) -> int:
    data = {
        "version": __version__,
        "detect": detect.detect_all(),
        "verify": verify.verify_all(None),
        "state": paths.load_json(paths.state_file()) or {},
    }
    _print_json(data)
    return 0


# ---------------------------------------------------------------------------
# interactive / first-run
# ---------------------------------------------------------------------------


def _interactive() -> int:
    print(f"nobrainer-browser v{__version__}")
    print("Cross-platform installer for four browser-automation tools.\n")
    print("Quick start:")
    print("  python -m nobrainer_browser detect")
    print("  python -m nobrainer_browser install playwright-mcp")
    print("  python -m nobrainer_browser wire both --tool playwright-mcp")
    print("  python -m nobrainer_browser verify\n")
    print("Run `python -m nobrainer_browser --help` for the full CLI.")
    snapshot = detect.detect_all()
    print("\nCurrent host snapshot:")
    _print_json(snapshot)
    return 0


# ---------------------------------------------------------------------------
# argparse plumbing
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nobrainer-browser",
        description="Install + wire browser-automation tools for Claude Code and Codex.",
    )
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd")

    # detect
    p_detect = sub.add_parser("detect", help="Print a JSON snapshot of host + tools + wiring.")
    p_detect.add_argument("--json", action="store_true", help="(default) JSON output")
    p_detect.set_defaults(func=_cmd_detect)

    # install
    p_install = sub.add_parser("install", help="Install one or all tools.")
    p_install.add_argument("target", choices=("all", *TOOL_KEYS),
                           help="Tool to install (or 'all').")
    p_install.add_argument("--cooldown-days", type=int, default=7,
                           help="npm supply-chain cooldown (default: 7).")
    p_install.add_argument("--dry-run", action="store_true",
                           help="Resolve versions and print commands without running them.")
    p_install.add_argument("--method", choices=t_ab.VALID_METHODS, default="npm",
                           help="Install method for agent-browser (default: npm).")
    p_install.add_argument("--with-deps", action="store_true",
                           help="Linux only: pass --with-deps to browser drivers post-install.")
    p_install.add_argument(
        "--mode", choices=t_ww.VALID_MODES, default="marketplace",
        help=("Webwright install mode (default: marketplace). 'source' clones "
              "the repo locally; required for openclaw/hermes hosts."),
    )
    p_install.add_argument(
        "--hosts", default=None,
        help=("Webwright: comma-separated subset of "
              f"{','.join(t_ww.VALID_HOSTS)} (default: claude,codex)."),
    )
    p_install.set_defaults(func=_cmd_install)

    # uninstall (webwright tool-level uninstall, distinct from MCP unwire)
    p_un = sub.add_parser(
        "tool-uninstall",
        help="Uninstall a tool. Currently supports: webwright.",
    )
    p_un.add_argument("target", choices=("webwright",),
                      help="Tool to uninstall.")
    p_un.add_argument(
        "--hosts", default=None,
        help=("Comma-separated subset of "
              f"{','.join(t_ww.VALID_HOSTS)} (default: all)."),
    )
    p_un.add_argument(
        "--purge-source", action="store_true",
        help="Also remove the local clone under <data_dir>/webwright.",
    )
    p_un.set_defaults(func=_cmd_uninstall)

    # wire
    p_wire = sub.add_parser("wire", help="Register an MCP server with Claude/Codex/both.")
    p_wire.add_argument("target", choices=("claude", "codex", "both"))
    p_wire.add_argument("--tool", default="playwright-mcp",
                        choices=("playwright-mcp",),
                        help="MCP server to wire (currently only playwright-mcp).")
    p_wire.add_argument("--cooldown-days", type=int, default=7)
    p_wire.set_defaults(func=_cmd_wire)

    # unwire
    p_unwire = sub.add_parser("unwire", help="Remove an MCP server from Claude/Codex/both.")
    p_unwire.add_argument("target", choices=("claude", "codex", "both"))
    p_unwire.add_argument("--tool", default="playwright-mcp",
                          choices=("playwright-mcp",))
    p_unwire.set_defaults(func=_cmd_unwire)

    # verify
    p_verify = sub.add_parser("verify", help="Health checks for installed tools and wiring.")
    p_verify.add_argument("--tool", action="append",
                          choices=(*TOOL_KEYS, "all"),
                          help="Restrict to one tool; repeatable.")
    p_verify.set_defaults(func=_cmd_verify)

    # status
    p_status = sub.add_parser("status", help="Combined detect + verify + state dump.")
    p_status.add_argument("--json", action="store_true")
    p_status.set_defaults(func=_cmd_status)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        return _interactive()
    return int(args.func(args) or 0)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
