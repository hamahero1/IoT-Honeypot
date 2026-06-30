#!/bin/bash

echo "========== CONTAINERS =========="
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo
echo "========== MEMORY =========="
free -h

echo
echo "========== DISK =========="
df -h /

echo
echo "========== UNIFIED EVENTS =========="
wc -l /opt/iot-honeypot/normalized/unified_events.jsonl 2>/dev/null

echo
echo "========== PREDICTIONS =========="
wc -l /opt/iot-honeypot/ml-engine/output/predictions.jsonl 2>/dev/null

echo
echo "========== ATTACK DISTRIBUTION =========="
python3 - <<'PY'
import json
from collections import Counter
path = "/opt/iot-honeypot/ml-engine/output/predictions.jsonl"
c = Counter()
try:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                row = json.loads(line)
                c[row.get("predicted_attack", "UNKNOWN")] += 1
    for k, v in c.most_common():
        print(f"{k}: {v}")
except FileNotFoundError:
    print("predictions file not found")
PY

echo
echo "========== LAST PIPELINE LOG =========="
tail -n 10 /opt/iot-honeypot/logs/pipeline_loop.log 2>/dev/null

echo
echo "========== LAST PREDICTOR LOG =========="
tail -n 20 /opt/iot-honeypot/logs/predictor_loop.log 2>/dev/null
