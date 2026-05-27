"""Interactive prompts. Stdlib only. Gracefully fall back to defaults on non-TTY.

All prompts respect EOF / KeyboardInterrupt and return the default rather than
crashing, so this module is safe to invoke from automation contexts.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional, Sequence


def _is_tty() -> bool:
    return sys.stdin is not None and sys.stdin.isatty()


def _prompt(text: str) -> Optional[str]:
    if not _is_tty():
        return None
    try:
        return input(text)
    except (EOFError, KeyboardInterrupt):
        return None


def ask(prompt: str, default: Optional[str] = None) -> Optional[str]:
    suffix = f" [{default}]" if default is not None else ""
    answer = _prompt(f"{prompt}{suffix}: ")
    if answer is None or answer.strip() == "":
        return default
    return answer.strip()


def ask_yes_no(prompt: str, default: bool = False) -> bool:
    default_label = "Y/n" if default else "y/N"
    answer = _prompt(f"{prompt} [{default_label}]: ")
    if answer is None or answer.strip() == "":
        return default
    return answer.strip().lower() in ("y", "yes", "true", "1")


def ask_choice(
    prompt: str,
    options: Sequence[str],
    default: Optional[str] = None,
) -> Optional[str]:
    if not options:
        return default
    if not _is_tty():
        return default if default in options else options[0]

    print(prompt)
    for i, opt in enumerate(options, start=1):
        marker = " (default)" if opt == default else ""
        print(f"  {i}) {opt}{marker}")
    answer = _prompt("Choice: ")
    if answer is None or answer.strip() == "":
        return default if default in options else options[0]
    answer = answer.strip()
    if answer.isdigit():
        idx = int(answer) - 1
        if 0 <= idx < len(options):
            return options[idx]
    if answer in options:
        return answer
    fallback = default if default in options else options[0]
    print(f"  unknown choice {answer!r}, using {fallback!r}", file=sys.stderr)
    return fallback


def ask_int(
    prompt: str,
    min_value: int,
    max_value: int,
    default: int,
) -> int:
    while True:
        answer = ask(prompt, str(default))
        if answer is None:
            return default
        try:
            value = int(answer)
        except ValueError:
            print(f"  not an integer: {answer!r}", file=sys.stderr)
            continue
        if min_value <= value <= max_value:
            return value
        print(
            f"  out of range [{min_value}..{max_value}]: {value}",
            file=sys.stderr,
        )


def ask_path(
    prompt: str,
    must_exist: bool = True,
    default: Optional[Path] = None,
) -> Optional[Path]:
    while True:
        answer = ask(prompt, str(default) if default else None)
        if answer is None:
            return default
        path = Path(answer).expanduser()
        if must_exist and not path.exists():
            print(f"  path does not exist: {path}", file=sys.stderr)
            if not _is_tty():
                return None
            continue
        return path
