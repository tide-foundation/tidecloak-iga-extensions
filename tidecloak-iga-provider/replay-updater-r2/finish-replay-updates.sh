#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-.}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bash "$DIR/fix-replay-package.sh" "$ROOT"
bash "$DIR/clean-legacy-tiderolerequests.sh" "$ROOT"
bash "$DIR/verify-replay-updates.sh" "$ROOT"
