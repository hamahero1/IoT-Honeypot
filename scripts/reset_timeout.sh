#!/bin/bash
# reset_timeout.sh — clear the HTTP honeypot routing timeout/flag for a source IP
# so it is evaluated fresh again (no longer stuck on the honeypot).
#
# Usage: reset_timeout.sh <ip>
#
# The HTTP proxy keeps IP state in memory and rewrites state_cache.json on every
# request, so a file edit alone would be clobbered. We stop the proxy, clear the
# IP's timeout/flag keys (and its flagged sessions), then start the proxy again —
# it reloads the cleaned state on start.

IP="${1:-}"
CACHE="/opt/iot-honeypot/router/state_cache.json"
PROXY="iot-http-router-proxy.service"

if [ -z "$IP" ]; then
  echo "usage: $(basename "$0") <ip>" >&2
  exit 1
fi

echo "Resetting honeypot timeout for $IP ..."
sudo systemctl stop "$PROXY"
# Always bring the proxy back, even if the edit fails.
trap 'sudo systemctl start "$PROXY" >/dev/null 2>&1 && echo "Proxy restarted — $IP routed fresh on its next request."' EXIT

sudo python3 - "$IP" "$CACHE" <<'PY'
import json, sys
ip, path = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        d = json.load(f)
except Exception as e:
    print(f"  could not read state cache: {e}")
    raise SystemExit(1)

ips = d.get("ips", {})
ent = ips.get(ip)
cleared = []
if ent:
    for k in ("http_flagged", "http_suspicious", "http_last_reason",
              "http_last_seen_utc", "http_timeout_until_utc",
              "flagged", "suspicious", "flagged_until_utc",
              "suspicious_until_utc"):
        if ent.pop(k, None) is not None:
            cleared.append(k)
else:
    print(f"  {ip} not in cache (already clear).")

sessions = d.get("sessions", {})
removed = [sid for sid, sv in list(sessions.items()) if sv.get("source_ip") == ip]
for sid in removed:
    del sessions[sid]

with open(path, "w") as f:
    json.dump(d, f, indent=2)

print(f"  cleared keys           : {', '.join(cleared) if cleared else 'none'}")
print(f"  removed flagged sessions: {len(removed)}")
PY
