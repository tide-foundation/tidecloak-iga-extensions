# Replay updater (round 2)

This bundle fixes the remaining import package mismatch and optionally removes the legacy `TideRoleRequests.java` if it's no longer referenced.

## Quick start

```bash
unzip replay-updater-r2.zip -d .
# checkpoint your work
git add -A && git commit -m "checkpoint before replay-updater-r2" || true

# run from the module/root that has your Java sources
bash replay-updater-r2/finish-replay-updates.sh .

# build
mvn -DskipTests package
```

### What each script does

- `fix-replay-package.sh`  
  Rewrites `org.tidecloak.tide.replay.TideRoleReplaySupport` → `org.tidecloak.tide.iga.replay.TideRoleReplaySupport` anywhere it finds the wrong package path.

- `clean-legacy-tiderolerequests.sh`  
  Checks if `TideRoleRequests.java` is still referenced by other files. If **not** referenced, deletes it. If referenced, it prints the list so you can migrate those callers first.

- `verify-replay-updates.sh`  
  Prints a summary of remaining old calls, wrong imports, and new calls to verify the migration.

- `finish-replay-updates.sh`  
  Runs the above three in sequence.
