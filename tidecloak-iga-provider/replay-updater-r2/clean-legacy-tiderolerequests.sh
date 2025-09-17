#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-.}"
echo "== Cleaning legacy TideRoleRequests if unused =="
echo "Root: $ROOT"
cd "$ROOT"

# locate the legacy file
FILE=""
if command -v git >/dev/null 2>&1; then
  FILE=$(git ls-files '*TideRoleRequests.java' 2>/dev/null | head -n1 || true)
fi
if [ -z "$FILE" ]; then
  FILE=$(find . -type f -name '*TideRoleRequests.java' | head -n1 || true)
fi

if [ -z "$FILE" ]; then
  echo "No TideRoleRequests.java found; nothing to remove."
  exit 0
fi

# check for external uses
mapfile -t USES < <(grep -RIl --exclude-dir=.git --include="*.java" 'TideRoleRequests' | grep -v "$FILE" || true)

if [ "${#USES[@]}" -eq 0 ]; then
  echo "No external references found; removing $FILE"
  if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git rm -f "$FILE" || rm -f "$FILE"
  else
    rm -f "$FILE"
  fi
else
  echo "Found external references to TideRoleRequests:"
  for u in "${USES[@]}"; do echo "  - $u"; done
  echo "Not deleting. Please migrate those references to TideRoleReplaySupport and re-run."
fi
