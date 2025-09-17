#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-.}"
echo "== Fixing import package to org.tidecloak.tide.iga.replay =="
echo "Root: $ROOT"
cd "$ROOT"

# choose sed variant cross-platform
if sed --version >/dev/null 2>&1; then
  SED=(sed -i)
else
  SED=(sed -i '')
fi

# find files with the wrong package path
mapfile -t FILES < <(grep -RIl --exclude-dir=.git --include="*.java" 'org\.tidecloak\.tide\.replay\.TideRoleReplaySupport' || true)

if [ "${#FILES[@]}" -eq 0 ]; then
  echo "No files with wrong package path found."
  exit 0
fi

for f in "${FILES[@]}"; do
  echo "Fixing: $f"
  "${SED[@]}" 's/org\.tidecloak\.tide\.replay\.TideRoleReplaySupport/org.tidecloak.tide.iga.replay.TideRoleReplaySupport/g' "$f"
done

echo "Done fixing package path."
