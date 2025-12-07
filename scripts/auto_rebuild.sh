#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

REBUILD_SCRIPT="$ROOT_DIR/scripts/rebuild.sh"
INTERVAL=${INTERVAL:-2}

if [[ ! -x "$REBUILD_SCRIPT" ]]; then
  echo "Making $REBUILD_SCRIPT executable" >&2
  chmod +x "$REBUILD_SCRIPT"
fi

hash_tree() {
  # Compute a stable hash of relevant files, ignoring build artifacts and deps
  find . \
    -path './.git' -prune -o \
    -path './.venv' -prune -o \
    -path './frontend/node_modules' -prune -o \
    -path './frontend/dist' -prune -o \
    -path './scan_artifacts' -prune -o \
    -type f -print0 \
    | sort -z \
    | xargs -0 sha256sum | sha256sum | awk '{print $1}'
}

LAST_HASH=""
echo "[auto-rebuild] Watching for changes (interval=${INTERVAL}s) ..."
while true; do
  H=$(hash_tree)
  if [[ "$H" != "$LAST_HASH" ]]; then
    echo "[auto-rebuild] Change detected at $(date -Is)"
    LAST_HASH="$H"
    bash "$REBUILD_SCRIPT" || echo "[auto-rebuild] Rebuild failed (will retry on next change)" >&2
  fi
  sleep "$INTERVAL"
done

