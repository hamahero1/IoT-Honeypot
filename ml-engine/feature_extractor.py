# ============================================================
# feature_extractor.py — IoT Honeypot ML Engine
# Ain Shams University — Cybersecurity Graduation Project 2026
#
# Reads live honeypot log files, groups events by source IP,
# and engineers numeric features for the ML model.
#
# SCHEMA NOTE (confirmed from server June 2026):
#   HTTP log (http_honeypot.jsonl) uses a DIFFERENT schema than
#   the original unified_events.jsonl:
#     - source_ip field is called 'ip'
#     - payload is in 'body'
#     - path is its own field (useful for scanner detection)
#     - no 'protocol' or 'event_type' fields
#
#   SSH log (ssh_router_events.jsonl) uses the expected schema:
#     - source_ip, protocol, event_type, username, password,
#       command, payload all present correctly
#
# FIXES APPLIED:
#   1. HTTP schema mapped correctly (ip→source_ip, body→payload, path extracted)
#   2. scanner_path_hits now checks the real 'path' field for HTTP events
#   3. login_attempts counts 401 responses AND SSH login_attempt event_type
#   4. response_status uses `is not None` check
#   5. __main__ block works correctly with list return type
# ============================================================

import os
import json
import pandas as pd
from datetime import datetime
from collections import defaultdict

# Bound how many lines are read per log file. The raw honeypot logs grow to
# 90-100 MB+; reading them whole every cycle is the main memory/CPU cost on a
# small box. We only need recent activity, so default to the tail. 0 = unlimited.
MAX_LINES_PER_LOG = int(os.environ.get("PREDICTOR_MAX_LINES_PER_LOG", "20000") or "0")


# ─────────────────────────────────────────────
# KNOWN PATTERNS
# ─────────────────────────────────────────────

EXPLOIT_STRINGS = [
    "../", "..\\/", "/etc/passwd", "/etc/shadow",
    "cmd=", "exec=", "eval(", "system(",
    "<script>", "SELECT ", "UNION ", "DROP TABLE",
    "wget ", "curl ", "/bin/sh", "/bin/bash",
    "phpinfo", "base64_decode", "nc -e"
]

KNOWN_SCANNER_PATHS = [
    "/admin", "/login", "/.env", "/config",
    "/wp-admin", "/phpmyadmin", "/manager",
    "/actuator", "/api/v1", "/.git",
    "/shell", "/cmd", "/console",
    "/setup", "/install", "/backup",
    "/cgi-bin", "/xmlrpc", "/wp-login",
]


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def load_logs(log_path, max_lines=MAX_LINES_PER_LOG):
    """Load entries from a JSONL log file. Skips missing files gracefully.

    When max_lines > 0, only the tail of the file is read (the most recent
    events) by seeking near the end — this keeps memory and CPU bounded on the
    very large raw honeypot logs instead of parsing the whole file every cycle.
    """
    entries = []
    try:
        if max_lines and max_lines > 0:
            with open(log_path, 'rb') as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                approx = min(size, max_lines * 700)   # ~700 bytes/line budget
                f.seek(size - approx)
                chunk = f.read()
            lines = chunk.decode('utf-8', 'ignore').split('\n')
            if approx < size and lines:
                lines = lines[1:]            # drop the partial first line
            lines = lines[-max_lines:]
        else:
            with open(log_path, 'r') as f:
                lines = f.readlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    except FileNotFoundError:
        pass
    return entries


def normalize_entry(entry, service):
    """
    Normalize a raw log entry to a consistent internal schema
    regardless of which honeypot service produced it.

    Returns a dict with these guaranteed keys:
        source_ip, protocol, event_type, username, password,
        command, payload, response_status, path, timestamp_utc
    """
    # Field-driven mapping so ANY log (honeypot, ingress, real-backend, rtsp)
    # parses correctly regardless of the service key — this lets the predictor
    # score every protocol and normal users, not just honeypot traffic.
    # Derive the protocol from the entry, falling back to the service key prefix.
    svc = str(service or '').lower()
    if svc.startswith('http'):
        svc_proto = 'http'
    elif svc.startswith('mqtt'):
        svc_proto = 'mqtt'
    elif svc.startswith('rtsp'):
        svc_proto = 'rtsp'
    elif svc.startswith('ssh'):
        svc_proto = 'ssh'
    else:
        svc_proto = svc or 'unknown'

    return {
        'source_ip'      : entry.get('source_ip') or entry.get('ip') or 'unknown',
        'protocol'       : entry.get('protocol') or svc_proto,
        'event_type'     : entry.get('event_type') or entry.get('event') or '',
        'username'       : entry.get('username'),
        'password'       : entry.get('password'),
        'command'        : entry.get('command'),
        'payload'        : str(entry.get('payload') or entry.get('body') or ''),
        'response_status': entry.get('response_status') if entry.get('response_status') is not None else entry.get('status_code'),
        'path'           : str(entry.get('path') or entry.get('rtsp_path') or ''),
        'timestamp_utc'  : entry.get('timestamp_utc') or entry.get('timestamp') or entry.get('ts') or '',
    }


def has_exploit_string(text):
    """Check if a string contains known exploit patterns."""
    if not text:
        return 0
    text_lower = str(text).lower()
    return int(any(sig.lower() in text_lower for sig in EXPLOIT_STRINGS))


def hits_known_scanner_path(text):
    """Check if text matches known scanner targets."""
    if not text:
        return 0
    text_lower = str(text).lower()
    return int(any(p in text_lower for p in KNOWN_SCANNER_PATHS))


def encode_protocol(protocol):
    """Encode protocol as a number."""
    mapping = {"http": 1, "ssh": 2, "mqtt": 3, "telnet": 4}
    return mapping.get(str(protocol).lower(), 0)


# ─────────────────────────────────────────────
# MAIN FEATURE EXTRACTION
# ─────────────────────────────────────────────

def extract_features(log_files):
    """
    Reads all log files, normalizes schemas, groups events by source IP,
    and engineers features per IP session.

    Args:
        log_files (dict): {
            'http': Path('/opt/.../http_honeypot.jsonl'),
            'ssh' : Path('/opt/.../ssh_router_events.jsonl'),
            'mqtt': Path('/opt/.../mqtt_honeypot.jsonl')
        }

    Returns:
        list of dicts — one dict per unique IP with all features + source_ip
    """

    # ── Load and normalize all logs ──
    all_entries = []
    for service, path in log_files.items():
        raw_entries = load_logs(path)
        for e in raw_entries:
            normalized = normalize_entry(e, service)
            normalized['_service'] = service
            all_entries.append(normalized)
        if raw_entries:
            print(f"  📂 {service}: {len(raw_entries)} entries loaded")

    if not all_entries:
        print("  ⚠️  No log entries found in any log file")
        return []

    print(f"  📦 Total entries: {len(all_entries)}")

    # ── Group events by source IP ──
    ip_events = defaultdict(list)
    for entry in all_entries:
        ip = entry.get("source_ip", "unknown")
        if ip in ('unknown', '', None, '172.17.0.1'):
            # Skip Docker internal IP and unknowns
            continue
        ip_events[ip].append(entry)

    print(f"  🌐 Unique external IPs: {len(ip_events)}")

    # ── Engineer features per IP ──
    rows = []

    for ip, events in ip_events.items():

        total_events   = len(events)
        protocols_used = set(e.get("protocol", "") for e in events)
        event_types    = [e.get("event_type", "") for e in events]
        payloads       = [e.get("payload", "") for e in events]
        paths          = [e.get("path", "") for e in events]     # HTTP path field
        commands       = [str(e.get("command", "") or "") for e in events]
        usernames      = [e.get("username") for e in events if e.get("username")]
        passwords      = [e.get("password") for e in events if e.get("password")]

        # FIX 4 — use `is not None` so status code 0 and 200 are never skipped
        statuses = [
            e.get("response_status")
            for e in events
            if e.get("response_status") is not None
        ]

        # ── Time-based features ──
        timestamps = []
        for e in events:
            try:
                ts = e.get("timestamp_utc", "")
                if ts:
                    timestamps.append(datetime.fromisoformat(ts.replace('Z', '+00:00')))
            except Exception:
                continue

        if len(timestamps) >= 2:
            timestamps.sort()
            duration_seconds = (timestamps[-1] - timestamps[0]).total_seconds()
            requests_per_min = (total_events / duration_seconds * 60) if duration_seconds > 0 else total_events
        else:
            duration_seconds = 0
            requests_per_min = total_events

        # ── Login / credential features ──
        # FIX 3 — count both HTTP 401 responses AND SSH login_attempt event_type
        login_attempts   = (
            sum(1 for s in statuses if s == 401) +          # HTTP 401s
            sum(1 for et in event_types if "login_attempt" in et.lower())  # SSH
        )
        login_successes  = sum(1 for et in event_types if "success" in et.lower())
        unique_usernames = len(set(usernames))
        unique_passwords = len(set(passwords))
        has_credentials  = int(len(usernames) > 0 or len(passwords) > 0)

        # ── Exploit / payload features ──
        exploit_in_payload = sum(has_exploit_string(p) for p in payloads)
        exploit_in_command = sum(has_exploit_string(c) for c in commands)
        # Also check paths for exploit patterns
        exploit_in_path    = sum(has_exploit_string(p) for p in paths)
        total_exploit_hits = exploit_in_payload + exploit_in_command + exploit_in_path
        has_exploit        = int(total_exploit_hits > 0)

        # ── Scanning features ──
        status_404_count  = sum(1 for s in statuses if s == 404)
        status_401_count  = sum(1 for s in statuses if s == 401)
        status_200_count  = sum(1 for s in statuses if s == 200)
        unique_statuses   = len(set(statuses))

        # FIX 2 — scanner_path_hits now checks the real HTTP 'path' field
        # This is much more accurate than checking the payload (which was always empty)
        # scanner_path_real_hits = deliberate hits on known sensitive/admin paths
        # (e.g. /admin, /wp-admin). Kept separate from the 404-inflation fallback
        # below so the predictor can treat a real /admin probe as recon on hit #1
        # while still soft-handling low-and-slow 404 noise.
        scanner_path_real_hits = sum(hits_known_scanner_path(p) for p in paths)
        # Also check payload as fallback for non-HTTP services
        scanner_path_real_hits += sum(hits_known_scanner_path(p) for p in payloads)
        scanner_path_hits = scanner_path_real_hits
        # If many 404s and no other scanner signals, treat 404s as scanner hits
        if status_404_count >= 3 and scanner_path_hits == 0:
            scanner_path_hits = status_404_count

        # ── Protocol / service features ──
        unique_protocols      = len(protocols_used)
        hit_multiple_services = int(unique_protocols > 1)
        protocol_encoded      = encode_protocol(list(protocols_used)[0]) if len(protocols_used) == 1 else 0

        # ── Command features (SSH) ──
        command_count       = sum(1 for et in event_types if "command" in et.lower())
        file_download_count = sum(1 for et in event_types if "download" in et.lower())

        # ── MQTT features ──
        mqtt_publish_count   = sum(1 for et in event_types if "publish" in et.lower())
        mqtt_subscribe_count = sum(1 for et in event_types if "subscri" in et.lower())

        rows.append({
            # Identity — kept for predictor enrichment, removed before model
            "source_ip"            : ip,

            # Volume
            "total_events"         : total_events,
            "requests_per_min"     : round(requests_per_min, 4),
            "duration_seconds"     : round(duration_seconds, 2),

            # Login
            "login_attempts"       : login_attempts,
            "login_successes"      : login_successes,
            "unique_usernames"     : unique_usernames,
            "unique_passwords"     : unique_passwords,
            "has_credentials"      : has_credentials,

            # Exploit
            "exploit_in_payload"   : exploit_in_payload,
            "exploit_in_command"   : exploit_in_command,
            "total_exploit_hits"   : total_exploit_hits,
            "has_exploit"          : has_exploit,

            # Scanning
            "scanner_path_hits"    : scanner_path_hits,
            "scanner_path_real_hits": scanner_path_real_hits,
            "status_404_count"     : status_404_count,
            "status_401_count"     : status_401_count,
            "status_200_count"     : status_200_count,
            "unique_statuses"      : unique_statuses,

            # Protocol
            "unique_protocols"     : unique_protocols,
            "hit_multiple_services": hit_multiple_services,
            "protocol_encoded"     : protocol_encoded,

            # SSH
            "command_count"        : command_count,
            "file_download_count"  : file_download_count,

            # MQTT
            "mqtt_publish_count"   : mqtt_publish_count,
            "mqtt_subscribe_count" : mqtt_subscribe_count,

            # Metadata (underscore-prefixed — dropped before the model by
            # the predictor's reindex to feature_columns). Used to order the
            # cycle most-recent-first so live attackers get predicted first.
            "_last_seen"           : (max(timestamps).isoformat() if timestamps else ""),
        })

    print(f"  ✅ Features extracted for {len(rows)} unique IPs")
    return rows


# ─────────────────────────────────────────────
# LOCAL TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    from pathlib import Path

    LOG_FILES = {
        "http": Path("/opt/iot-honeypot/logs/http_honeypot.jsonl"),
        "ssh" : Path("/opt/iot-honeypot/logs/ssh_router_events.jsonl"),
        "mqtt": Path("/opt/iot-honeypot/logs/mqtt_honeypot.jsonl"),
    }

    print("🔍 Running feature extractor test...")
    rows = extract_features(LOG_FILES)

    if rows:
        df = pd.DataFrame(rows)
        print("\n📊 Non-zero feature counts (what the model can actually see):")
        for col in df.drop(columns=["source_ip"]).columns:
            non_zero = (df[col] != 0).sum()
            if non_zero > 0:
                print(f"   {col:<30} non-zero: {non_zero}/{len(df)}   max: {df[col].max()}")

        print(f"\n📊 Sample rows (top 5 by total_events):")
        print(df.sort_values('total_events', ascending=False).head(5)[
            ['source_ip', 'total_events', 'requests_per_min',
             'login_attempts', 'scanner_path_hits', 'status_404_count',
             'has_exploit', 'unique_passwords', 'protocol_encoded']
        ].to_string())

        print(f"\nShape: {df.shape}")
        df.to_csv("extracted_features_test.csv", index=False)
        print("✅ Saved to extracted_features_test.csv")
    else:
        print("⚠️  No features extracted — check log file paths")
