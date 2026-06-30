#!/bin/bash
set -euo pipefail

PROJECT_DIR="/opt/iot-honeypot"
BACKUP_DIR="${PROJECT_DIR}/mqtt/rollback"
LAST_FILE="${BACKUP_DIR}/last_public_container.txt"

if [ ! -f "$LAST_FILE" ]; then
  echo "No MQTT public-backend backup container recorded."
  exit 1
fi

BACKUP_NAME="$(cat "$LAST_FILE")"

systemctl stop iot-mqtt-router-proxy.service >/dev/null 2>&1 || true

if docker inspect mqtt-device >/dev/null 2>&1; then
  docker stop mqtt-device >/dev/null 2>&1 || true
  docker rm mqtt-device >/dev/null 2>&1 || true
fi

docker rename "$BACKUP_NAME" mqtt-device
docker start mqtt-device

echo "Restored mqtt-device public broker from ${BACKUP_NAME}"
