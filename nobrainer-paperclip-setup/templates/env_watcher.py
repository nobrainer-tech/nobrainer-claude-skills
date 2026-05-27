#!/usr/bin/env python3
"""Standalone env URL watcher invoked by the scheduler every 2 minutes.

Reads a state file path from argv[1], pings each URL in ``env_watchers``,
writes the results next to the state file as ``<state>.env_status.json``.

Stdlib only. Never raises. Designed to be triggered by launchd / systemd /
schtasks without any Python environment beyond the system interpreter.

Security:
- Only ``http://`` and ``https://`` schemes are accepted.
- Private/loopback/link-local IPs are refused unless the URL explicitly uses
  ``localhost``, ``127.0.0.1``, or ``::1`` (the intentional dev allowlist).
- Redirects are NOT followed — a 30x is reported as ``redirect-blocked`` so
  a misconfigured watcher can never be used to pivot onto an internal host.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import socket
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

_ALLOWED_LOCALHOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401, ANN001
        return None


def _is_private_host(host: str) -> bool:
    """True if ``host`` resolves to ANY private/loopback/link-local address."""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        # If we cannot resolve, treat as private to err on the side of safety.
        return True
    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return True
    return False


def _check(url: str, timeout: float = 5.0) -> dict:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return {"ok": False, "status": f"refused-scheme-{parsed.scheme or 'none'}"}
    host = (parsed.hostname or "").lower()
    if host not in _ALLOWED_LOCALHOSTS and _is_private_host(host):
        return {"ok": False, "status": f"refused-private-host:{host}"}

    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(url, timeout=timeout) as resp:  # noqa: S310
            if 200 <= resp.status < 500:
                return {"ok": True, "status": f"up-{resp.status}"}
            return {"ok": False, "status": f"http-{resp.status}"}
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            return {"ok": False, "status": "redirect-blocked"}
        # 4xx is reachable but unauthorized / not found — still "up".
        return {"ok": True, "status": f"up-{exc.code}"}
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
        return {"ok": False, "status": f"down: {type(exc).__name__}"}


def _atomic_write(path: Path, content: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: env_watcher.py <state-file.json>", file=sys.stderr)
        return 2
    state_path = Path(argv[1])
    if not state_path.exists():
        print(f"state file missing: {state_path}", file=sys.stderr)
        return 1
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"unreadable state: {exc}", file=sys.stderr)
        return 1

    out: dict[str, object] = {
        "ran_at": _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "services": [],
    }
    for watcher in state.get("env_watchers", []) or []:
        name = watcher.get("name")
        url = watcher.get("url")
        if not url:
            continue
        result = _check(url)
        out["services"].append({"name": name, "url": url, "status": result["status"]})

    status_path = state_path.with_suffix(".env_status.json")
    _atomic_write(status_path, json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
