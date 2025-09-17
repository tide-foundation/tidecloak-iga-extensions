#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${1:-.}"
echo "== Verify Tide Replay updates =="
echo "Root: ${ROOT_DIR}"
echo

echo "-- Remaining old calls (should be 0) --"
grep -R --line-number -E "\bTideRoleRequests\.(createRoleAuthorizerPolicyDraft|commitRoleAuthorizerPolicy)\s*\(|org\.tidecloak\.base\.iga\.TideRequests\.TideRoleRequests\.(createRoleAuthorizerPolicyDraft|commitRoleAuthorizerPolicy)" "${ROOT_DIR}" --include \*.java || true
echo

echo "-- New calls (should be >0 if you had any) --"
grep -R --line-number -E "\bTideRoleReplaySupport\.(createRoleAuthorizerPolicyDraft|commitRoleAuthorizerPolicy)\s*\(|org\.tidecloak\.tide\.iga\.replay\.TideRoleReplaySupport\.(createRoleAuthorizerPolicyDraft|commitRoleAuthorizerPolicy)" "${ROOT_DIR}" --include \*.java || true
echo

echo "-- Import lines --"
grep -R --line-number -E "^\s*import\s+org\.tidecloak\.(base\.iga\.TideRequests|tide\.iga\.replay)\." "${ROOT_DIR}" --include \*.java || true
