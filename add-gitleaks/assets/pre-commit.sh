#!/usr/bin/env bash
# Native git pre-commit hook fallback (used when no pre-commit/lefthook framework).
# Install per-clone:  ln -sf ../../scripts/gitleaks-precommit.sh .git/hooks/pre-commit
# NOTE: git hooks are NOT shared across clones — prefer the pre-commit framework for team coverage.
set -euo pipefail

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "gitleaks not installed — skipping scan (install: brew install gitleaks)" >&2
  exit 0
fi

CONFIG_FLAG=""
[ -f .gitleaks.toml ] && CONFIG_FLAG="--config .gitleaks.toml"

if ! gitleaks git --staged --redact -v $CONFIG_FLAG; then
  echo "" >&2
  echo "gitleaks found a potential secret in staged changes — commit blocked." >&2
  echo "Remove the secret, or if it's a false positive, add an allowlist entry to .gitleaks.toml." >&2
  exit 1
fi
