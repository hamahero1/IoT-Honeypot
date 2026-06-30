#!/bin/bash
cd /opt/iot-honeypot
exec /opt/iot-honeypot/dashboard_api/venv/bin/uvicorn dashboard_api.app:app --host 0.0.0.0 --port 8501
