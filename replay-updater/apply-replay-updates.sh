#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${1:-.}"

echo "== Tide Replay updater: switching TideRoleRequests -> TideRoleReplaySupport =="
echo "Root: ${ROOT_DIR}"
echo

# Detect GNU vs BSD sed (macOS)
if sed --version >/dev/null 2>&1; then
  SED="sed -i"
else
  SED="sed -i ''"
fi

update_file() {
  local f="$1"
  # function calls (unqualified)
  $SED -E 's/\bTideRoleRequests\.createRoleAuthorizerPolicyDraft\s*\(/TideRoleReplaySupport.createRoleAuthorizerPolicyDraft(/g' "$f"
  $SED -E 's/\bTideRoleRequests\.commitRoleAuthorizerPolicy\s*\(/TideRoleReplaySupport.commitRoleAuthorizerPolicy(/g' "$f"

  # fully-qualified calls
  $SED -E 's/org\.tidecloak\.base\.iga\.TideRequests\.TideRoleRequests\.createRoleAuthorizerPolicyDraft/org.tidecloak.tide.iga.replay.TideRoleReplaySupport.createRoleAuthorizerPolicyDraft/g' "$f"
  $SED -E 's/org\.tidecloak\.base\.iga\.TideRequests\.TideRoleRequests\.commitRoleAuthorizerPolicy/org.tidecloak.tide.iga.replay.TideRoleReplaySupport.commitRoleAuthorizerPolicy/g' "$f"

  # imports (specific + wildcard)
  $SED -E 's|^\s*import\s+org\.tidecloak\.base\.iga\.TideRequests\.TideRoleRequests;|import org.tidecloak.tide.iga.replay.TideRoleReplaySupport;|g' "$f"
  $SED -E 's|^\s*import\s+org\.tidecloak\.base\.iga\.TideRequests\.\*;|import org.tidecloak.tide.iga.replay.TideRoleReplaySupport;|g' "$f"
}

count_before=$(grep -R --line-number -E "\bTideRoleRequests\.(createRoleAuthorizerPolicyDraft|commitRoleAuthorizerPolicy)\s*\(|org\.tidecloak\.base\.iga\.TideRequests\.TideRoleRequests\.(createRoleAuthorizerPolicyDraft|commitRoleAuthorizerPolicy)" "${ROOT_DIR}" --include \*.java | wc -l | tr -d ' ')
echo "Found ${count_before} usage(s) to update."
echo

# Apply updates
while IFS= read -r -d '' file; do
  update_file "$file"
done < <(find "${ROOT_DIR}" -type f -name "*.java" -print0)

count_after=$(grep -R --line-number -E "\bTideRoleRequests\.(createRoleAuthorizerPolicyDraft|commitRoleAuthorizerPolicy)\s*\(|org\.tidecloak\.base\.iga\.TideRequests\.TideRoleRequests\.(createRoleAuthorizerPolicyDraft|commitRoleAuthorizerPolicy)" "${ROOT_DIR}" --include \*.java | wc -l | tr -d ' ')
echo
echo "Remaining matches after update: ${count_after}"
if [ "${count_after}" != "0" ]; then
  echo "NOTE: some references remain; please inspect grep output above."
fi

echo "Done."
