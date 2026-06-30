#!/bin/bash
set -euo pipefail

PROJECT_DIR="/opt/iot-honeypot"
LOG_FILE="${PROJECT_DIR}/logs/pipeline_event.log"
LOCK_FILE="${PROJECT_DIR}/logs/pipeline_event.lock"

mkdir -p "${PROJECT_DIR}/logs"

{
  flock -n 9 || exit 0

  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] pipeline_event start" >> "${LOG_FILE}"

  export REBUILD_MAX_LINES_PER_SOURCE="${REBUILD_MAX_LINES_PER_SOURCE:-5000}"
  export REBUILD_MAX_SSH_FILES="${REBUILD_MAX_SSH_FILES:-7}"
  export REBUILD_PROTOCOL_FILTER="${REBUILD_PROTOCOL_FILTER:-http,mqtt,rtsp,ssh}"
  export OMP_NUM_THREADS="${OMP_NUM_THREADS:-1}"
  export OPENBLAS_NUM_THREADS="${OPENBLAS_NUM_THREADS:-1}"
  export MKL_NUM_THREADS="${MKL_NUM_THREADS:-1}"
  export NUMEXPR_NUM_THREADS="${NUMEXPR_NUM_THREADS:-1}"

  cd "${PROJECT_DIR}"
  /usr/bin/python3 "${PROJECT_DIR}/router/rtsp_log_router.py" --max-lines "${REBUILD_MAX_LINES_PER_SOURCE}" >> "${LOG_FILE}" 2>&1
  /usr/bin/python3 "${PROJECT_DIR}/router/ssh_log_router.py" --max-lines "${REBUILD_MAX_LINES_PER_SOURCE}" --max-files "${REBUILD_MAX_SSH_FILES}" >> "${LOG_FILE}" 2>&1
  echo "[1/1] Rebuilding unified events..." >> "${LOG_FILE}"
  /usr/bin/python3 "${PROJECT_DIR}/rebuild_unified_events.py" >> "${LOG_FILE}" 2>&1

  echo "Predictor service handles feature extraction and ML from normalized events." >> "${LOG_FILE}"

  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] pipeline_event done" >> "${LOG_FILE}"
} 9>"${LOCK_FILE}"
