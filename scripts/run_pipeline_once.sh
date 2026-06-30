#!/bin/bash
set -e

echo "[1/2] Rebuilding unified events..."
python3 /opt/iot-honeypot/rebuild_unified_events.py

echo "[2/2] Running feature extractor..."
cd /opt/iot-honeypot/ml-engine
source venv/bin/activate
python feature_extractor.py

echo "Pipeline once completed."
