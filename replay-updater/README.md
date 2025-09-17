# Tide Replay Updater (TideRoleRequests -> TideRoleReplaySupport)

This bundle finds and replaces **old** calls to:
- `TideRoleRequests.createRoleAuthorizerPolicyDraft(...)`
- `TideRoleRequests.commitRoleAuthorizerPolicy(...)`

with the **new** replay API:
- `TideRoleReplaySupport.createRoleAuthorizerPolicyDraft(...)`
- `TideRoleReplaySupport.commitRoleAuthorizerPolicy(...)`

It also updates `import org.tidecloak.base.iga.TideRequests.TideRoleRequests;`
to `import org.tidecloak.tide.iga.replay.TideRoleReplaySupport;`

> Assumes the new support class lives at `org.tidecloak.tide.iga.replay.TideRoleReplaySupport`.

## Usage

From the **module root** that contains your Java code (e.g., `tidecloak-iga-provider`):

```bash
# Dry commit first
git add -A && git commit -m "pre-replay-updater checkpoint" || true

# Apply replacements in the current directory
bash replay-updater/apply-replay-updates.sh .

# Verify
bash replay-updater/verify-replay-updates.sh .

# Build
mvn -DskipTests package
```

### macOS note
On macOS, BSD `sed` needs: `sed -i ''`. The script auto-detects and uses the correct flag.

## What it touches
- Any `*.java` under the given root dir.
- Replaces method calls and import lines listed above.
- Leaves everything else untouched.

## Troubleshooting
- If you still see references to `TideRoleRequests`, run:
  ```bash
  grep -R --line-number -E "\bTideRoleRequests\.|org\.tidecloak\.base\.iga\.TideRequests\.TideRoleRequests\." . --include \*.java
  ```
  and adjust manually — you may have custom wrapper helpers.

- If the package of `TideRoleReplaySupport` differs in your tree, update the import replacement in the script.
