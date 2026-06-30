#!/bin/bash
set -euo pipefail

WATCH_INTERVAL_SECONDS="${PIPELINE_WATCH_INTERVAL_SECONDS:-2}"
DEBOUNCE_SECONDS="${PIPELINE_WATCH_DEBOUNCE_SECONDS:-2}"
RUN_ON_STARTUP="${PIPELINE_RUN_ON_STARTUP:-1}"
WATCH_LOG="/opt/iot-honeypot/logs/pipeline_watch.log"

WATCHED_PATHS=(
  "/opt/iot-honeypot/logs/http_honeypot.jsonl"
  "/opt/iot-honeypot/logs/http_ingress_80.jsonl"
  "/opt/iot-honeypot/logs/routing_decisions.jsonl"
  "/opt/iot-honeypot/logs/http_real_28080.jsonl"
  "/opt/iot-honeypot/logs/mqtt_router_messages.jsonl"
  "/opt/iot-honeypot/rtsp/logs/mediamtx.log"
  "/opt/iot-honeypot/logs/rtsp_router_events.jsonl"
  "/opt/iot-honeypot/logs/cowrie/cowrie.json"
)

declare -A LAST_MTIME

get_mtime() {
  local path="$1"
  if [ -e "$path" ]; then
    stat -c %Y "$path" 2>/dev/null || echo 0
    return
  fi
  echo 0
}

refresh_mtimes() {
  local path
  for path in "${WATCHED_PATHS[@]}"; do
    LAST_MTIME["$path"]="$(get_mtime "$path")"
  done
}

log_watch() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >> "$WATCH_LOG"
}

mkdir -p /opt/iot-honeypot/logs
refresh_mtimes

log_watch "watcher started"
for path in "${WATCHED_PATHS[@]}"; do
  log_watch "watching $path"
done

if [ "$RUN_ON_STARTUP" = "1" ]; then
  log_watch "startup run requested"
  /opt/iot-honeypot/run_pipeline_event.sh || true
fi

while true; do
  changed_path=""

  for path in "${WATCHED_PATHS[@]}"; do
    current_mtime="$(get_mtime "$path")"
    if [ "${LAST_MTIME[$path]}" != "$current_mtime" ]; then
      LAST_MTIME["$path"]="$current_mtime"
      changed_path="$path"
    fi
  done

  if [ -n "$changed_path" ]; then
    log_watch "detected change in $changed_path"
    sleep "$DEBOUNCE_SECONDS"
    refresh_mtimes
    /opt/iot-honeypot/run_pipeline_event.sh || true
  fi

  sleep "$WATCH_INTERVAL_SECONDS"
done
