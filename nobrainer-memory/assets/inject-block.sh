#!/usr/bin/env bash
# Idempotently injects the NB-WIKI-MEMORY block into a client's always-on file.
# Usage: VAULT=... HOST=... inject-block.sh <target-file>
set -euo pipefail

TARGET="${1:?provide the target file, e.g. ~/.claude/CLAUDE.md}"
: "${VAULT:?set VAULT}"
: "${HOST:?set HOST}"

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BLOCK="$(sed -e "s#{{VAULT}}#${VAULT}#g" -e "s#{{HOST}}#${HOST}#g" "$SKILL_DIR/block.md")"

mkdir -p "$(dirname "$TARGET")"
touch "$TARGET"

# remove the existing block (between markers, inclusive)
awk '
  /<!-- NB-WIKI-MEMORY:START -->/ { skip=1 }
  !skip { print }
  /<!-- NB-WIKI-MEMORY:END -->/ { skip=0 }
' "$TARGET" > "$TARGET.nbtmp"

# append the fresh block (one blank line as separator)
{ cat "$TARGET.nbtmp"; printf '\n%s\n' "$BLOCK"; } > "$TARGET"
rm -f "$TARGET.nbtmp"

echo "OK: NB-WIKI-MEMORY injected into $TARGET"
