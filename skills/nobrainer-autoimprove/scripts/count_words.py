#!/usr/bin/env python3
"""Count whitespace-delimited words in raw or newline-escaped text."""

from __future__ import annotations

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--escaped-newlines", action="store_true")
    args = parser.parse_args()
    text = sys.stdin.read()
    if args.escaped_newlines:
        text = text.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\r", "\n")
    print(len(text.split()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
