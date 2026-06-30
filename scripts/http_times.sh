#!/bin/bash
# http_times.sh — show the times a source IP hit the HTTP honeypot.
#
# Usage:  http_times.sh <ip> [max_rows]
#   <ip>       source IP to look up (required)
#   [max_rows] how many most-recent hits to show (default 50)
#
# Reads logs/http_honeypot.jsonl and prints, per request:
#   <timestamp_utc>  <method>  <status>  <path>
# plus a first-seen / last-seen / count summary.

IP="${1:-}"
MAX="${2:-50}"
LOG="/opt/iot-honeypot/logs/http_honeypot.jsonl"

if [ -z "$IP" ]; then
  echo "usage: $(basename "$0") <ip> [max_rows]" >&2
  exit 1
fi
if [ ! -f "$LOG" ]; then
  echo "honeypot log not found: $LOG" >&2
  exit 1
fi

grep -F "\"ip\": \"$IP\"" "$LOG" | python3 -c '
import json, sys
ip = sys.argv[1]
mx = int(sys.argv[2])
rows = []
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        rows.append(json.loads(line))
    except Exception:
        continue
if not rows:
    print("No HTTP honeypot activity for " + ip + ".")
    raise SystemExit
shown = rows[-mx:]
print("HTTP honeypot hits for " + ip + ":")
print("-" * 78)
for d in shown:
    ts = str(d.get("timestamp_utc", "-"))
    method = str(d.get("method", "-"))
    status = str(d.get("response_status", "-"))
    path = str(d.get("path", "-"))
    print(f"{ts:28}  {method:4}  {status:>4}  {path}")
print("-" * 78)
first = str(rows[0].get("timestamp_utc"))
last = str(rows[-1].get("timestamp_utc"))
print(f"{len(shown)} of {len(rows)} hit(s) shown  |  first: {first}  |  last: {last}")
' "$IP" "$MAX"
