"""Supply-chain hardened npm/npx wrapper.

Every package install pins to the latest version published at least
``cooldown_days`` ago (default 7). This protects against freshly compromised
packages that haven't yet been flagged by the community (the ``chalk``,
``debug`` and ``ua-parser-js`` incidents all weaponised versions that were
hours-to-days old when they hit unsuspecting installers).

Resolution flow:

  1. ``npm view <pkg> time --json`` returns ``{<version>: <iso8601>, ...}``.
  2. We pick the highest published version whose publish date is
     ``<= now - cooldown``.
  3. We invoke ``npm install -g <pkg>@<resolved>`` or
     ``npx <pkg>@<resolved> ...``.

If the registry is unreachable, the function raises a typed error so the
caller can decide to abort or proceed with explicit user consent.

Setting env var ``NPM_SAFE_BYPASS=1`` disables the cooldown for the current
process; useful only for debugging.

Stdlib only. No subprocess shell. All long-running invocations are tee'd to
``paths.logs_dir()/npm-safe/<ts>-<cmd>-<pkg>.log``.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable

from . import paths

DEFAULT_COOLDOWN_DAYS = 7
DEFAULT_TIMEOUT = 30
_RESERVED_TIME_KEYS = frozenset({"created", "modified"})
_BYPASS_ENV = "NPM_SAFE_BYPASS"

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-+]+)?$")


class NpmSafeError(Exception):
    """Raised when a safe version cannot be resolved or npm/npx is missing."""


def check_bypass() -> bool:
    """True iff ``NPM_SAFE_BYPASS=1`` in env. Emits a loud stderr warning."""
    if os.environ.get(_BYPASS_ENV) == "1":
        print(
            "[npm-safe] WARNING: NPM_SAFE_BYPASS=1 is set; supply-chain "
            "cooldown is DISABLED for this process. This is unsafe.",
            file=sys.stderr,
        )
        return True
    return False


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def _require_npm() -> str:
    npm = shutil.which("npm")
    if not npm:
        raise NpmSafeError("npm not found in PATH (install Node >= 20)")
    return npm


def _require_npx() -> str:
    npx = shutil.which("npx")
    if not npx:
        raise NpmSafeError("npx not found in PATH (install Node >= 20)")
    return npx


def _parse_iso(value: str) -> _dt.datetime:
    """Parse an ISO-8601 timestamp from the npm registry. Always UTC."""
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = _dt.datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc)


def _npm_view_time(package: str, timeout: int) -> dict:
    """Run ``npm view <pkg> time --json`` and return ``{version: datetime}``."""
    npm = _require_npm()
    try:
        proc = subprocess.run(  # noqa: S603
            [npm, "view", package, "time", "--json"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        raise NpmSafeError(f"npm view failed for {package!r}: {exc}") from exc

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip().splitlines()
        tail = stderr[-1] if stderr else f"rc={proc.returncode}"
        raise NpmSafeError(f"npm view {package!r} failed: {tail}")

    raw = (proc.stdout or "").strip()
    if not raw:
        raise NpmSafeError(f"npm view {package!r} returned no JSON")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise NpmSafeError(f"npm view {package!r} returned malformed JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise NpmSafeError(f"npm view {package!r} returned non-object: {type(data).__name__}")

    times: dict[str, _dt.datetime] = {}
    for version, ts in data.items():
        if version in _RESERVED_TIME_KEYS:
            continue
        if not isinstance(version, str) or not isinstance(ts, str):
            continue
        if not _SEMVER_RE.match(version):
            continue
        try:
            times[version] = _parse_iso(ts)
        except ValueError:
            continue
    if not times:
        raise NpmSafeError(f"no parsable versions in npm view {package!r}")
    return times


def _semver_key(version: str) -> tuple:
    """Sort key: numeric (major, minor, patch), then prerelease lower than release."""
    base, _, pre = version.partition("-")
    pre = pre.split("+", 1)[0]
    try:
        major, minor, patch = (int(x) for x in base.split("."))
    except ValueError:
        return (0, 0, 0, 1, ())
    if pre == "":
        return (major, minor, patch, 1, ())
    parts: list[tuple[int, int | str]] = []
    for chunk in pre.split("."):
        if chunk.isdigit():
            parts.append((0, int(chunk)))
        else:
            parts.append((1, chunk))
    return (major, minor, patch, 0, tuple(parts))


def _pick_safe(times: dict, cutoff: _dt.datetime) -> str:
    """Return the highest semver whose publish date is <= cutoff."""
    eligible = [(v, ts) for v, ts in times.items() if ts <= cutoff]
    if not eligible:
        newest_ts = max(times.values())
        raise NpmSafeError(
            f"no version published on/before {cutoff.isoformat()} "
            f"(newest is {newest_ts.isoformat()})"
        )
    eligible.sort(key=lambda vt: (_semver_key(vt[0]), vt[1]), reverse=True)
    return eligible[0][0]


def resolve_safe_version(
    package: str,
    *,
    cooldown_days: int = DEFAULT_COOLDOWN_DAYS,
    timeout: int = DEFAULT_TIMEOUT,
) -> str:
    """Return the latest version published >= ``cooldown_days`` ago."""
    if not package or not isinstance(package, str):
        raise NpmSafeError("package must be a non-empty string")
    if cooldown_days < 0:
        raise NpmSafeError("cooldown_days must be >= 0")

    if check_bypass():
        return "latest"

    times = _npm_view_time(package, timeout=timeout)
    cutoff = _dt.datetime.now(tz=_dt.timezone.utc) - _dt.timedelta(days=cooldown_days)
    return _pick_safe(times, cutoff)


def _age_days(times: dict, version: str) -> float | None:
    ts = times.get(version)
    if ts is None:
        return None
    delta = _dt.datetime.now(tz=_dt.timezone.utc) - ts
    return round(delta.total_seconds() / 86400.0, 2)


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


def _log_file(kind: str, package: str) -> Path:
    log_dir = paths.logs_dir() / "npm-safe"
    log_dir.mkdir(parents=True, exist_ok=True)
    slug = paths.slugify(package, separator="-")
    return log_dir / f"{paths.now_utc_compact()}-{kind}-{slug}.log"


def _run_npm(
    args: list[str],
    log_file: Path,
    *,
    timeout: int | None = None,
    env: dict | None = None,
) -> int:
    """Run ``npm``/``npx`` with stdout+stderr tee'd to ``log_file``."""
    print(f"[npm-safe] running: {' '.join(args)}")
    print(f"[npm-safe] log: {log_file}")
    try:
        with log_file.open("w", encoding="utf-8") as fh:
            proc = subprocess.Popen(  # noqa: S603
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
            )
            assert proc.stdout is not None
            try:
                for line in proc.stdout:
                    fh.write(line)
                    fh.flush()
                    sys.stdout.write(line)
                return proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                raise NpmSafeError(f"command timed out after {timeout}s: {' '.join(args)}")
    except (FileNotFoundError, OSError) as exc:
        raise NpmSafeError(f"failed to invoke {args[0]!r}: {exc}") from exc


def install_global(
    package: str,
    *,
    cooldown_days: int = DEFAULT_COOLDOWN_DAYS,
    dry_run: bool = False,
    timeout: int | None = None,
) -> dict:
    """``npm install -g <pkg>@<safe-version>``."""
    npm = _require_npm()
    if check_bypass():
        version = "latest"
        age_days: float | None = None
    else:
        times = _npm_view_time(package, timeout=DEFAULT_TIMEOUT)
        cutoff = _dt.datetime.now(tz=_dt.timezone.utc) - _dt.timedelta(days=cooldown_days)
        version = _pick_safe(times, cutoff)
        age_days = _age_days(times, version)

    spec = f"{package}@{version}"
    args = [npm, "install", "-g", spec]
    log_file = _log_file("install", package)
    if dry_run:
        print(f"[npm-safe] dry-run: would run {' '.join(args)}")
        return {
            "package": package,
            "version": version,
            "age_days": age_days,
            "rc": 0,
            "log_path": str(log_file),
            "dry_run": True,
        }
    rc = _run_npm(args, log_file, timeout=timeout)
    return {
        "package": package,
        "version": version,
        "age_days": age_days,
        "rc": rc,
        "log_path": str(log_file),
        "dry_run": False,
    }


def run_npx(
    package: str,
    args: Iterable[str],
    *,
    cooldown_days: int = DEFAULT_COOLDOWN_DAYS,
    env: dict | None = None,
    timeout: int | None = None,
) -> int:
    """``npx <pkg>@<safe-version> <args...>``."""
    npx = _require_npx()
    version = resolve_safe_version(package, cooldown_days=cooldown_days)
    spec = f"{package}@{version}"
    argv = [npx, "-y", spec, *args]
    log_file = _log_file("npx", package)
    return _run_npm(argv, log_file, timeout=timeout, env=env)


if __name__ == "__main__":  # pragma: no cover
    try:
        v = resolve_safe_version("tar", cooldown_days=7)
        print(f"safe tar version: {v}")
    except NpmSafeError as exc:
        print(f"resolve failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
