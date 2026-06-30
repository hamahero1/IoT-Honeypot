import json
import os

INPUT_FILE = "/opt/iot-honeypot/tmp/mqtt_all.jsonl"
OUTPUT_FILE = "/opt/iot-honeypot/normalized/unified_events.jsonl"

seen = set()

if os.path.exists(OUTPUT_FILE):
    with open(OUTPUT_FILE, "r") as out:
        for line in out:
            line = line.strip()
            if line:
                seen.add(line)

with open(INPUT_FILE, "r") as f, open(OUTPUT_FILE, "a") as out:
    for line in f:
        line = line.strip()
        if not line:
            continue

        data = json.loads(line)

        event = {
            "timestamp_utc": data.get("ts"),
            "source_ip": data.get("ip"),
            "protocol": "mqtt",
            "event_type": data.get("event", "message"),
            "username": None,
            "password": None,
            "command": None,
            "payload": data.get("payload"),
            "response_status": None
        }

        event_line = json.dumps(event, ensure_ascii=False)

        if event_line not in seen:
            out.write(event_line + "\n")
            seen.add(event_line)
