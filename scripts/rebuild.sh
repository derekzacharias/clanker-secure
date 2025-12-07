#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="clanker"
CONTAINER_NAME="clanker-ui"
PORT_MAPPING="8181:8000"

echo "[rebuild] Building Docker image: ${IMAGE_NAME}"
docker build -t "${IMAGE_NAME}" .

echo "[rebuild] Stopping existing container (if any): ${CONTAINER_NAME}"
docker stop "${CONTAINER_NAME}" >/dev/null 2>&1 || true
docker rm "${CONTAINER_NAME}" >/dev/null 2>&1 || true

echo "[rebuild] Starting container: ${CONTAINER_NAME} on ${PORT_MAPPING}"
RUN_CMD=("uvicorn" "clanker.main:app" "--host" "0.0.0.0" "--port" "8000")
if [[ -f "overlay/main_override.py" ]]; then
  echo "[rebuild] Using main_override app entrypoint"
  RUN_CMD=("uvicorn" "main_override:app" "--host" "0.0.0.0" "--port" "8000")
fi

DOCKER_RUN=(docker run -d --name "${CONTAINER_NAME}" -p ${PORT_MAPPING} --cap-add=NET_ADMIN)

# Ensure persistent data directories exist and migrate old DB if present
mkdir -p data scan_artifacts
if [[ -f clanker.db && ! -f data/clanker.db ]]; then
  echo "[rebuild] Migrating existing clanker.db -> data/clanker.db"
  cp -f clanker.db data/clanker.db
fi

# Bind overlay files if present (override backend without rebuilding image)
if [[ -d overlay ]]; then
  echo "[rebuild] Binding overlay into container at /app/overlay and extending PYTHONPATH (/app/src first)"
  DOCKER_RUN+=( -v "$(pwd)/overlay:/app/overlay:ro" -e PYTHONPATH=/app/src:/app/overlay )
else
  DOCKER_RUN+=( -e PYTHONPATH=/app/src )
fi

# Pass through optional admin seed env vars if defined
if [[ -n "${CLANKER_ADMIN_EMAIL:-}" ]]; then
  DOCKER_RUN+=( -e CLANKER_ADMIN_EMAIL="${CLANKER_ADMIN_EMAIL}" )
fi
if [[ -n "${CLANKER_ADMIN_PASSWORD:-}" ]]; then
  DOCKER_RUN+=( -e CLANKER_ADMIN_PASSWORD="${CLANKER_ADMIN_PASSWORD}" )
fi

# Pass through optional NVD API key if defined
if [[ -n "${NVD_API_KEY:-}" ]]; then
  DOCKER_RUN+=( -e NVD_API_KEY="${NVD_API_KEY}" )
fi

# Persist database and artifacts across restarts
DOCKER_RUN+=( -v "$(pwd)/data:/app/data" -e DATABASE_URL=sqlite:////app/data/clanker.db )
DOCKER_RUN+=( -v "$(pwd)/scan_artifacts:/app/scan_artifacts" )

"${DOCKER_RUN[@]}" "${IMAGE_NAME}" "${RUN_CMD[@]}"

echo "[rebuild] Done. Open http://localhost:8181/app/ (or your host IP)"
