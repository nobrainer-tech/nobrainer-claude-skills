#!/usr/bin/env bash
# Idempotentnie wstrzykuje blok NB-WIKI-MEMORY do pliku always-on klienta.
# Użycie: VAULT=... HOST=... inject-block.sh <target-file>
set -euo pipefail

TARGET="${1:?podaj plik docelowy, np. ~/.claude/CLAUDE.md}"
: "${VAULT:?ustaw VAULT}"
: "${HOST:?ustaw HOST}"

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BLOCK="$(sed -e "s#{{VAULT}}#${VAULT}#g" -e "s#{{HOST}}#${HOST}#g" "$SKILL_DIR/block.md")"

mkdir -p "$(dirname "$TARGET")"
touch "$TARGET"

# usuń istniejący blok (między markerami włącznie)
awk '
  /<!-- NB-WIKI-MEMORY:START -->/ { skip=1 }
  !skip { print }
  /<!-- NB-WIKI-MEMORY:END -->/ { skip=0 }
' "$TARGET" > "$TARGET.nbtmp"

# dopisz świeży blok (jedna pusta linia separatora)
{ cat "$TARGET.nbtmp"; printf '\n%s\n' "$BLOCK"; } > "$TARGET"
rm -f "$TARGET.nbtmp"

echo "OK: NB-WIKI-MEMORY wstrzyknięty do $TARGET"
