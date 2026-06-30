import json
import os
import re
import subprocess

OUTPUT_FILE = "/opt/iot-honeypot/normalized/unified_events.jsonl"

logs = subprocess.check_output(
    "cat /opt/iot-honeypot/tmp/rtsp_all.log 2>/dev/null",
    shell=True
).decode()

seen = set()
if os.path.exists(OUTPUT_FILE):
    with open(OUTPUT_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                seen.add(line)

with open(OUTPUT_FILE, "a") as out:
    for line in logs.splitlines():
        if "[conn" not in line:
            continue

        ts = re.search(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})', line)
        ip = re.search(r'\[conn ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):\d+\]', line)

        if not ip:
            continue

        event_type = "connection_opened" if " opened" in line else "connection_closed" if " closed:" in line else "connection"

        event = {
            "timestamp_utc": ts.group(1).replace("/", "-").replace(" ", "T") + "Z" if ts else None,
            "source_ip": ip.group(1),
            "protocol": "rtsp",
            "event_type": event_type,
            "username": None,
            "password": None,
            "command": None,
            "payload": line,
            "response_status": None
        }

        event_line = json.dumps(event, ensure_ascii=False)

        if event_line not in seen:
            out.write(event_line + "\n")
            seen.add(event_line)
