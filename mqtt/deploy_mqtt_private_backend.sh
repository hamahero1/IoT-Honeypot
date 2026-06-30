#!/bin/bash
set -euo pipefail

PROJECT_DIR="/opt/iot-honeypot"
BACKUP_DIR="${PROJECT_DIR}/mqtt/rollback"
STAMP="$(date -u +%Y%m%d-%H%M%S)"
BACKUP_NAME="mqtt-device-public-backup-${STAMP}"

mkdir -p "$BACKUP_DIR"

if docker inspect mqtt-device >/dev/null 2>&1; then
  docker inspect mqtt-device > "${BACKUP_DIR}/${BACKUP_NAME}.inspect.json"
  docker stop mqtt-device >/dev/null 2>&1 || true
  docker rename mqtt-device "$BACKUP_NAME"
  echo "$BACKUP_NAME" > "${BACKUP_DIR}/last_public_container.txt"
fi

docker run -d \
  --name mqtt-device \
  --network iot-net \
  --restart unless-stopped \
  -p 127.0.0.1:11883:1883 \
  -v "${PROJECT_DIR}/mqtt/config/mosquitto.conf:/mosquitto/config/mosquitto.conf:ro" \
  -v "${PROJECT_DIR}/mqtt/data:/mosquitto/data" \
  -v "${PROJECT_DIR}/mqtt/logs:/mosquitto/log" \
  eclipse-mosquitto:latest \
  /usr/sbin/mosquitto -c /mosquitto/config/mosquitto.conf

echo "mqtt-device is now private on 127.0.0.1:11883"
echo "Previous public container, if present, was renamed to ${BACKUP_NAME}"
