#!/usr/bin/env bash
set -euo pipefail

# Basic smoke test for a running Clanker instance.
# Allows optional auth checks when credentials are provided via env.

BASE_URL="${BASE_URL:-http://localhost:8181}"
EMAIL="${CLANKER_EMAIL:-}"
PASSWORD="${CLANKER_PASSWORD:-}"
SCAN_TARGET="${SMOKE_SCAN_TARGET:-127.0.0.1}"
RUN_SCAN_SMOKE="${RUN_SCAN_SMOKE:-1}"

log() {
  echo "[smoke] $*"
}

fatal() {
  echo "[smoke][error] $*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fatal "Missing required command: $1"
}

require_cmd curl
require_cmd python3

log "Checking HTTP reachability at ${BASE_URL}"
curl -fsSL "${BASE_URL}" >/dev/null || fatal "HTTP check failed"

if [[ -n "$EMAIL" && -n "$PASSWORD" ]]; then
  log "Authenticating as ${EMAIL}"
  login_json=$(curl -fsSL -X POST "${BASE_URL}/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${EMAIL}\",\"password\":\"${PASSWORD}\"}") || fatal "Login failed"

  token=$(python3 - <<'PY'
import json, os, sys
try:
    data = json.load(sys.stdin)
    token = data.get("access_token")
    if not token:
        raise ValueError("access_token missing")
    print(token)
except Exception as exc:
    raise SystemExit(f"failed to parse access_token: {exc}")
PY
  <<<"$login_json") || fatal "Unable to parse access_token"

  log "Fetched access token; verifying /auth/me"
  curl -fsSL "${BASE_URL}/auth/me" -H "Authorization: Bearer ${token}" >/dev/null || fatal "/auth/me failed"

  if [[ "$RUN_SCAN_SMOKE" != "0" ]]; then
    uniq=$(date +%s)
    log "Creating disposable asset for smoke scan (${SCAN_TARGET})"
    asset_resp=$(curl -fsSL -X POST "${BASE_URL}/assets" \
      -H "Authorization: Bearer ${token}" \
      -H "Content-Type: application/json" \
      -d "{\"name\":\"smoke-${uniq}\",\"target\":\"${SCAN_TARGET}\"}") || fatal "Asset creation failed"

    asset_id=$(python3 - <<'PY'
import json, sys
data=json.load(sys.stdin)
aid=data.get("id")
if not aid:
    raise SystemExit("id missing")
print(aid)
PY
    <<<"$asset_resp") || fatal "Unable to parse asset id"

    log "Enqueuing scan against asset ${asset_id} (profile: quick)"
    scan_resp=$(curl -fsSL -X POST "${BASE_URL}/scans" \
      -H "Authorization: Bearer ${token}" \
      -H "Content-Type: application/json" \
      -d "{\"asset_ids\":[${asset_id}],\"profile\":\"quick\"}") || fatal "Scan creation failed"

    scan_id=$(python3 - <<'PY'
import json, sys
data=json.load(sys.stdin)
sid=data.get("id")
if not sid:
    raise SystemExit("id missing")
print(sid)
PY
    <<<"$scan_resp") || fatal "Unable to parse scan id"

    log "Polling scan ${scan_id} until completion (timeout 120s)"
    end=$((SECONDS + 120))
    status="queued"
    while [[ $SECONDS -lt $end ]]; do
      detail=$(curl -fsSL "${BASE_URL}/scans/${scan_id}" -H "Authorization: Bearer ${token}") || fatal "Failed to fetch scan detail"
      status=$(python3 - <<'PY'
import json, sys
data=json.load(sys.stdin)
print(data.get("status","unknown"))
PY
      <<<"$detail")
      log "Scan ${scan_id} status: ${status}"
      case "$status" in
        completed|completed_with_errors|failed|cancelled)
          break
          ;;
      esac
      sleep 5
    done
    if [[ "$status" != "completed" && "$status" != "completed_with_errors" && "$status" != "failed" && "$status" != "cancelled" ]]; then
      fatal "Scan ${scan_id} did not complete within timeout (last status: ${status})"
    fi
  fi
fi

log "Smoke test completed successfully"
