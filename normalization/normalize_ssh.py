import json
from pathlib import Path

input_file = Path("/opt/iot-honeypot/tmp/cowrie_all.json")
output_file = Path("/opt/iot-honeypot/normalized/unified_events.jsonl")

EVENT_MAP = {
    "cowrie.session.connect": "connection_opened",
    "cowrie.session.closed": "connection_closed",
    "cowrie.login.failed": "login_attempt",
    "cowrie.login.success": "login_success",
    "cowrie.command.input": "command_executed",
    "cowrie.session.file_download": "file_download",
}

with input_file.open("r") as infile, output_file.open("a") as outfile:
    for line in infile:
        line = line.strip()
        if not line:
            continue

        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        eventid = event.get("eventid", "unknown")

        normalized_event = {
            "timestamp_utc": event.get("timestamp"),
            "source_ip": event.get("src_ip"),
            "protocol": "ssh",
            "event_type": EVENT_MAP.get(eventid, eventid),
            "username": event.get("username"),
            "password": event.get("password"),
            "command": event.get("input"),
            "payload": event.get("message"),
            "response_status": None
        }

        outfile.write(json.dumps(normalized_event) + "\n")
