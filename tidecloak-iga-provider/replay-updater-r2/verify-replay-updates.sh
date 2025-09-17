#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-.}"
echo "== Verify Tide Replay updates =="
echo "Root: $ROOT"
cd "$ROOT"

echo
echo "-- Remaining old calls (should be 0) --"
grep -RIn --exclude-dir=.git --include="*.java" 'TideRoleRequests\.(createRoleAuthorizerPolicyDraft|commitRoleAuthorizerPolicy)\s*\(' || true

echo
echo "-- Wrong package imports (should be 0) --"
grep -RIn --exclude-dir=.git --include="*.java" 'org\.tidecloak\.tide\.replay\.TideRoleReplaySupport' || true

echo
echo "-- New calls (should be >0 if you had any) --"
grep -RIn --exclude-dir=.git --include="*.java" 'TideRoleReplaySupport\.(createRoleAuthorizerPolicyDraft|commitRoleAuthorizerPolicy)\s*\(' || true

echo
echo "-- Import lines --"
grep -RIn --exclude-dir=.git --include="*.java" '^import .*TideRoleReplaySupport' || true
