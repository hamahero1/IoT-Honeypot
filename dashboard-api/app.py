from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
import secrets
import threading
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import monotonic
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


BASE = Path("/opt/iot-honeypot")
UNIFIED_PATH = BASE / "normalized" / "unified_events.jsonl"
PREDICTIONS_PATH = BASE / "ml-engine" / "output" / "predictions.jsonl"
ROUTING_PATH = BASE / "logs" / "routing_decisions.jsonl"

MAX_EVENTS = int(os.environ.get("DASHBOARD_MAX_EVENTS", "50000"))
WINDOW_PACKETS = int(os.environ.get("DASHBOARD_WINDOW_PACKETS", "5000"))
MAX_PREDICTIONS = int(os.environ.get("DASHBOARD_MAX_PREDICTIONS", "5000"))
MAX_ROUTES = int(os.environ.get("DASHBOARD_MAX_ROUTES", "50000"))
# /api/paths scans the routing log on each call; on the small box a 50k-line
# synchronous scan can block the single worker long enough to stall the whole
# dashboard. Bound it separately and conservatively.
MAX_PATHS_SCAN = int(os.environ.get("DASHBOARD_PATHS_SCAN_LINES", "15000"))
MAX_MAP_POINTS = int(os.environ.get("DASHBOARD_MAX_MAP_POINTS", "160"))
MAX_IP_DETAILS = int(os.environ.get("DASHBOARD_MAX_IP_DETAILS", "5000"))
RECENT_LIMIT = int(os.environ.get("DASHBOARD_RECENT_LIMIT", "120"))
SNAPSHOT_MAX_AGE_SECONDS = float(os.environ.get("DASHBOARD_SNAPSHOT_MAX_AGE_SECONDS", "15"))
WS_SNAPSHOT_INTERVAL_SECONDS = float(os.environ.get("DASHBOARD_WS_SNAPSHOT_INTERVAL_SECONDS", "10"))
LINE_COUNT_CACHE: dict[str, tuple[int, int, int]] = {}
ROUTE_SPLIT_CACHE: dict[str, tuple[int, int, tuple[int, int]]] = {}
UNIQUE_IPS_CACHE: dict[str, tuple[int, int, int]] = {}
RFC1918_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.", "192.168.", "127.")
TRACKED_PROTOCOLS = ("http", "mqtt", "rtsp", "ssh")
PROTOCOL_LABELS = {
    "all": "Mixed",
    "http": "HTTP",
    "mqtt": "MQTT",
    "rtsp": "RTSP",
    "ssh": "SSH",
}
RAW_EVENT_PATHS = (
    BASE / "logs" / "routing_decisions.jsonl",
    BASE / "logs" / "http_ingress_80.jsonl",
    BASE / "logs" / "http_real_28080.jsonl",
    BASE / "logs" / "http_honeypot.jsonl",
    BASE / "logs" / "mqtt_ingress_1883.jsonl",
    BASE / "logs" / "mqtt_messages.jsonl",
    BASE / "logs" / "mqtt_real.jsonl",
    BASE / "logs" / "mqtt_router_messages.jsonl",
    BASE / "logs" / "mqtt_honeypot.jsonl",
    BASE / "logs" / "rtsp_router_events.jsonl",
    BASE / "rtsp" / "logs" / "mediamtx.log",
)
SNAPSHOT_PATHS = (UNIFIED_PATH, PREDICTIONS_PATH, ROUTING_PATH)
SNAPSHOT_CACHE_LOCK = threading.Lock()
SNAPSHOT_CACHE: dict[str, Any] | None = None
# Cache the parsed dataset (events/predictions/routes) so endpoints like
# /api/ip and /api/events don't re-read and JSON-parse tens of thousands of
# JSONL lines on every request. On the small 1GB box this reparse was the main
# cause of the API backlogging (drawer ML fields appeared blank because the
# /api/ip fetch took 25s+ behind the /api/summary polling flood).
DATASET_MAX_AGE_SECONDS = float(os.environ.get("DASHBOARD_DATASET_MAX_AGE_SECONDS", "8"))
DATASET_CACHE_LOCK = threading.Lock()
DATASET_CACHE: tuple[list[dict[str, Any]], dict[str, dict[str, Any]], list[dict[str, Any]]] | None = None
DATASET_SIGNATURE: tuple[tuple[str, int], ...] | None = None
DATASET_GENERATED_MONOTONIC = 0.0
SNAPSHOT_SIGNATURE: tuple[tuple[str, int], ...] | None = None
SNAPSHOT_GENERATED_MONOTONIC = 0.0

HONEYPOT_LOG_PATH = BASE / "logs" / "http_honeypot.jsonl"

_DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")
_AUTH_ENABLED = bool(_DASHBOARD_PASSWORD)
_AUTH_TOKEN = hashlib.sha256(_DASHBOARD_PASSWORD.encode()).hexdigest() if _DASHBOARD_PASSWORD else ""
_HTTP_BEARER = HTTPBearer(auto_error=False)


def verify_auth(credentials: HTTPAuthorizationCredentials | None = Depends(_HTTP_BEARER)) -> None:
    if not _AUTH_ENABLED:
        return
    if credentials is None or not secrets.compare_digest(credentials.credentials, _AUTH_TOKEN):
        raise HTTPException(status_code=401, detail="Unauthorized")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_ts(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except Exception:
        return default


def read_jsonl_tail(path: Path, max_rows: int) -> list[dict[str, Any]]:
    if not path.exists() or max_rows <= 0:
        return []

    raw_lines: deque[bytes] = deque(maxlen=max_rows)
    chunk_size = 1024 * 1024
    carry = b""

    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        position = handle.tell()
        while position > 0 and len(raw_lines) < max_rows:
            read_size = min(chunk_size, position)
            position -= read_size
            handle.seek(position)
            chunk = handle.read(read_size) + carry
            parts = chunk.splitlines()
            if position > 0 and parts:
                carry = parts[0]
                parts = parts[1:]
            else:
                carry = b""

            for line in reversed(parts):
                if line.strip():
                    raw_lines.appendleft(line)
                    if len(raw_lines) >= max_rows:
                        break

    rows: list[dict[str, Any]] = []
    for raw_line in raw_lines:
        try:
            value = json.loads(raw_line.decode("utf-8", errors="ignore"))
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def count_lines_cached(path: Path) -> int:
    if not path.exists():
        return 0

    stat = path.stat()
    cache_key = str(path)
    cached = LINE_COUNT_CACHE.get(cache_key)
    if cached and cached[0] == stat.st_mtime_ns and cached[1] == stat.st_size:
        return cached[2]

    total = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            total += chunk.count(b"\n")

    if stat.st_size > 0:
        with path.open("rb") as handle:
            handle.seek(max(0, stat.st_size - 1))
            if handle.read(1) != b"\n":
                total += 1

    LINE_COUNT_CACHE[cache_key] = (stat.st_mtime_ns, stat.st_size, total)
    return total


def count_raw_events_from_start() -> int:
    files = list(RAW_EVENT_PATHS)
    cowrie_dir = BASE / "logs" / "cowrie"
    if cowrie_dir.exists():
        files.extend(sorted(cowrie_dir.glob("cowrie.json*")))
    return sum(count_lines_cached(path) for path in files if path.exists())


def count_route_split_from_start(path: Path = UNIFIED_PATH) -> tuple[int, int]:
    """Lifetime (honeypot, real) counts across every event in unified_events.jsonl.

    Lets the Attack-share tile reflect the true lifetime split instead of the
    deduplicated 8k window. Cached by file (mtime, size) like the line counter.
    """
    if not path.exists():
        return (0, 0)

    stat = path.stat()
    cache_key = str(path)
    cached = ROUTE_SPLIT_CACHE.get(cache_key)
    if cached and cached[0] == stat.st_mtime_ns and cached[1] == stat.st_size:
        return cached[2]

    honey = real = 0
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            decision = str(row.get("route_decision") or "").lower()
            if decision == "honeypot":
                honey += 1
            elif decision == "real":
                real += 1

    ROUTE_SPLIT_CACHE[cache_key] = (stat.st_mtime_ns, stat.st_size, (honey, real))
    return (honey, real)


def count_unique_sources_from_start(path: Path = UNIFIED_PATH) -> int:
    """Distinct source IPs across every event in unified_events.jsonl.

    The windowed snapshot only sees IPs from the most-recent 8k events, so the
    "Unique sources / lifetime" tile badly undercounts. Cached by (mtime, size).
    """
    if not path.exists():
        return 0

    stat = path.stat()
    cache_key = str(path)
    cached = UNIQUE_IPS_CACHE.get(cache_key)
    if cached and cached[0] == stat.st_mtime_ns and cached[1] == stat.st_size:
        return cached[2]

    ips: set[str] = set()
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip = row.get("source_ip")
            if ip and ip != "unknown":
                ips.add(normalize_ip(ip))

    total = len(ips)
    UNIQUE_IPS_CACHE[cache_key] = (stat.st_mtime_ns, stat.st_size, total)
    return total


def dataset_signature(paths: tuple[Path, ...] = SNAPSHOT_PATHS) -> tuple[tuple[str, int], ...]:
    return tuple((str(path), path.stat().st_mtime_ns if path.exists() else 0) for path in paths)


def normalize_ip(value: Any) -> str:
    text = str(value or "").strip()
    if "," in text:
        text = text.split(",", 1)[0].strip()
    return text or "unknown"


def is_private_or_local(ip: str) -> bool:
    return ip.startswith(RFC1918_PREFIXES)


def risk_rank(risk: str) -> int:
    risk = str(risk or "").lower()
    if risk == "critical":
        return 4
    if risk == "high":
        return 3
    if risk == "medium":
        return 2
    if risk == "low":
        return 1
    return 0


def infer_risk(event: dict[str, Any], prediction: dict[str, Any] | None = None) -> str:
    direct_risk = str(event.get("risk_level") or "")
    if direct_risk.lower() in {"critical", "high", "medium", "low"}:
        return direct_risk

    if prediction:
        risk = str(prediction.get("risk_level") or "")
        if risk:
            return risk

    score = safe_float(event.get("router_score", event.get("score")), 0)
    route = str(event.get("route_decision") or "").lower()
    # score 999 is the router's "session already flagged" sentinel, not a
    # severity. A flagged/honeypot session is High; real severity (Critical)
    # only comes from an explicit ML prediction risk_level handled above.
    if route == "honeypot" or score >= 5:
        return "High"
    if score >= 3:
        return "Medium"
    return "Low"


def attack_category(predicted_attack: Any) -> str:
    text = str(predicted_attack or "").lower()
    if "bruteforce" in text or "dictionary" in text:
        return "Brute Force"
    if "scan" in text or "recon" in text or "probe" in text:
        return "Scanning"
    if "exploit" in text or "command" in text or "sql" in text or "xss" in text:
        return "Exploit"
    if "ddos" in text or "dos" in text:
        return "DoS"
    if "router_flagged" in text or "honeypot" in text:
        return "Router Flagged"
    return "Normal"


def derive_attack_label(event: dict[str, Any], prediction: dict[str, Any] | None = None) -> str:
    predicted = str((prediction or {}).get("predicted_attack") or "").strip()
    if predicted and predicted.lower() not in {"unknown", "unclassified", "none", "null"}:
        return predicted

    protocol = str(event.get("protocol") or "").lower()
    event_type = str(event.get("event_type") or event.get("event") or "").lower()
    route = str(event.get("route_decision") or "").lower()
    score = safe_float(event.get("router_score", event.get("score")), 0)

    if route == "honeypot" or score >= 3:
        if protocol == "ssh":
            return "SSH_Routed_To_Honeypot"
        if protocol == "http":
            return "Router_Flagged_HTTP"
        if protocol == "mqtt":
            return "MQTT_Suspicious_Activity"
        if protocol == "rtsp":
            return "RTSP_Suspicious_Probe"
        return "Router_Flagged_Activity"

    if protocol == "ssh":
        if "login" in event_type or "auth" in event_type or "password" in event_type:
            return "SSH_BruteForce_Attempt"
        if "command" in event_type:
            return "SSH_Command_Activity"
        if "fingerprint" in event_type or "version" in event_type or "connection" in event_type:
            return "Simple_SSH_Probe"
        return "SSH_Observed"

    if protocol == "http":
        return "Normal_HTTP_User"
    if protocol == "mqtt":
        return "Normal_MQTT_Client"
    if protocol == "rtsp":
        return "Normal_RTSP_Client"
    return "Observed_Activity"


def packet_is_attack(packet: dict[str, Any]) -> bool:
    route = str(packet.get("route_decision") or "").lower()
    score = safe_float(packet.get("score"), 0)
    predicted = str(packet.get("predicted_attack") or "").lower()
    risk = risk_rank(str(packet.get("risk_level") or ""))
    has_router_signal = route in {"real", "honeypot"} or packet.get("score") not in {None, ""}

    if route == "honeypot" or score >= 3:
        return True
    if has_router_signal:
        return False
    if risk >= 2 and "normal" not in predicted:
        return True
    return attack_category(predicted) != "Normal" and "unclassified" not in predicted


def latest_predictions(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for row in rows:
        ip = normalize_ip(row.get("source_ip"))
        previous = latest.get(ip)
        if previous is None:
            latest[ip] = row
            continue
        if (parse_ts(row.get("timestamp_utc")) or datetime.min.replace(tzinfo=timezone.utc)) >= (
            parse_ts(previous.get("timestamp_utc")) or datetime.min.replace(tzinfo=timezone.utc)
        ):
            latest[ip] = row
    return latest


def event_timestamp_key(event: dict[str, Any]) -> datetime:
    return parse_ts(event.get("timestamp_utc") or event.get("ts")) or datetime.min.replace(tzinfo=timezone.utc)


def prediction_for_event(event: dict[str, Any], predictions: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    return predictions.get(normalize_ip(event.get("source_ip")))


def event_summary(event: dict[str, Any], predictions: dict[str, dict[str, Any]]) -> dict[str, Any]:
    prediction = prediction_for_event(event, predictions)
    ip = normalize_ip(event.get("source_ip"))
    timestamp = event.get("timestamp_utc") or event.get("ts") or ""
    risk = infer_risk(event, prediction)
    attack = derive_attack_label(event, prediction)
    payload = event.get("payload")
    if isinstance(payload, (dict, list)):
        payload = json.dumps(payload, ensure_ascii=False)

    return {
        "timestamp_utc": timestamp,
        "source_ip": ip,
        "protocol": str(event.get("protocol") or "unknown").lower(),
        "event_type": event.get("event_type") or event.get("event") or "event",
        "log_origin": event.get("log_origin"),
        "risk_level": risk,
        "risk_rank": risk_rank(risk),
        "predicted_attack": attack,
        "route_decision": event.get("route_decision"),
        "routed_to": event.get("routed_to"),
        "score": event.get("router_score", event.get("score")),
        "path": event.get("path"),
        "topic": event.get("topic"),
        "payload": str(payload or "")[:300],
        "decision_id": event.get("decision_id"),
        "session_id": event.get("session_id"),
        "client_id": event.get("client_id"),
    }


def deterministic_geo(ip: str) -> dict[str, Any]:
    parts = [safe_int(part, 0) for part in re.findall(r"\d+", ip)[:4]]
    while len(parts) < 4:
        parts.append(0)
    seed = (parts[0] * 97 + parts[1] * 53 + parts[2] * 29 + parts[3] * 11) % 10000
    lat = ((seed % 1400) / 10.0) - 70.0
    lon = (((seed * 37) % 3400) / 10.0) - 170.0
    return {"lat": round(lat, 2), "lon": round(lon, 2), "estimated": True}


def build_heatmap(events: list[dict[str, Any]], predictions: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    buckets = {(now - timedelta(hours=hour)).isoformat(): Counter() for hour in range(23, -1, -1)}
    ordered_keys = list(buckets.keys())
    start = now - timedelta(hours=23)

    for event in events:
        ts = event_timestamp_key(event)
        if ts < start:
            continue
        bucket = ts.replace(minute=0, second=0, microsecond=0).isoformat()
        if bucket not in buckets:
            continue
        risk = infer_risk(event, prediction_for_event(event, predictions))
        buckets[bucket][risk] += 1

    output = []
    max_count = max((sum(counter.values()) for counter in buckets.values()), default=1) or 1
    for key in ordered_keys:
        counter = buckets[key]
        total = sum(counter.values())
        output.append(
            {
                "hour": key,
                "label": parse_ts(key).strftime("%H:%M") if parse_ts(key) else key,
                "total": total,
                "critical": counter.get("Critical", 0),
                "high": counter.get("High", 0),
                "medium": counter.get("Medium", 0),
                "low": counter.get("Low", 0),
                "intensity": round(total / max_count, 3),
            }
        )
    return output


def build_protocol_breakdown(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts = Counter(str(event.get("protocol") or "unknown").lower() for event in events)
    return [{"name": key, "value": value} for key, value in counts.most_common()]


def packet_key(packet: dict[str, Any], index: int) -> str:
    decision_id = str(packet.get("decision_id") or "").strip()
    if decision_id:
        return f"decision:{decision_id}"

    return "|".join(
        [
            str(packet.get("timestamp_utc") or index),
            normalize_ip(packet.get("source_ip")),
            str(packet.get("protocol") or "unknown").lower(),
            str(packet.get("event_type") or "event"),
            str(packet.get("path") or packet.get("topic") or packet.get("payload") or ""),
        ]
    )


def dedupe_packets(summarized: list[dict[str, Any]]) -> list[dict[str, Any]]:
    packets: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(summarized):
        key = packet_key(row, index)
        existing = packets.get(key)
        if existing is None:
            packets[key] = row
            continue

        existing_rank = risk_rank(str(existing.get("risk_level") or ""))
        row_rank = risk_rank(str(row.get("risk_level") or ""))
        if row_rank > existing_rank:
            packets[key] = row
            continue

        if row_rank == existing_rank and event_timestamp_key(row) > event_timestamp_key(existing):
            packets[key] = row

    return sorted(packets.values(), key=lambda row: row.get("timestamp_utc") or "", reverse=True)


def build_protocol_dashboards(packets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    protocol_stats = {
        protocol: {
            "protocol": protocol,
            "label": PROTOCOL_LABELS[protocol],
            "total_packets": 0,
            "attacked_packets": 0,
            "normal_packets": 0,
            "router_station_events": 0,
            "source_events": 0,
            "honeypot_events": 0,
            "real_events": 0,
            "latest_event_at": None,
        }
        for protocol in TRACKED_PROTOCOLS
    }

    for packet in packets:
        protocol = str(packet.get("protocol") or "unknown").lower()
        if protocol not in protocol_stats:
            continue

        item = protocol_stats[protocol]
        item["total_packets"] += 1
        is_router_station = (
            str(packet.get("event_type") or "").lower() == "router_decision"
            or str(packet.get("log_origin") or "").lower() == "routing_decisions"
        )
        route = str(packet.get("route_decision") or "").lower()
        routed_to = str(packet.get("routed_to") or "").lower()
        is_attack = packet_is_attack(packet)
        if is_router_station:
            item["router_station_events"] += 1
        else:
            item["source_events"] += 1
        if route == "honeypot" or "honeypot" in routed_to:
            item["honeypot_events"] += 1
        elif route == "real" or routed_to.startswith("real_"):
            item["real_events"] += 1
        elif is_attack:
            item["honeypot_events"] += 1
        else:
            item["real_events"] += 1
        if is_attack:
            item["attacked_packets"] += 1
        else:
            item["normal_packets"] += 1

        timestamp = packet.get("timestamp_utc")
        if timestamp and (not item["latest_event_at"] or timestamp > item["latest_event_at"]):
            item["latest_event_at"] = timestamp

    mixed = {
        "protocol": "all",
        "label": PROTOCOL_LABELS["all"],
        "total_packets": sum(item["total_packets"] for item in protocol_stats.values()),
        "attacked_packets": sum(item["attacked_packets"] for item in protocol_stats.values()),
        "normal_packets": sum(item["normal_packets"] for item in protocol_stats.values()),
        "router_station_events": sum(item["router_station_events"] for item in protocol_stats.values()),
        "source_events": sum(item["source_events"] for item in protocol_stats.values()),
        "honeypot_events": sum(item["honeypot_events"] for item in protocol_stats.values()),
        "real_events": sum(item["real_events"] for item in protocol_stats.values()),
        "latest_event_at": max(
            (item["latest_event_at"] for item in protocol_stats.values() if item["latest_event_at"]),
            default=None,
        ),
    }

    output = [mixed, *[protocol_stats[protocol] for protocol in TRACKED_PROTOCOLS]]
    for item in output:
        total = item["total_packets"] or 0
        item["attack_rate"] = round((item["attacked_packets"] / total) * 100, 2) if total else 0
    return output


def protocol_breakdown_from_dashboards(dashboards: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {"name": item["label"], "value": item["total_packets"]}
        for item in dashboards
        if item["protocol"] != "all"
    ]


def build_attack_map(events: list[dict[str, Any]], predictions: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for event in events:
        ip = normalize_ip(event.get("source_ip"))
        if ip == "unknown":
            continue
        prediction = predictions.get(ip)
        risk = infer_risk(event, prediction)
        is_attack = packet_is_attack(event)
        timestamp = event.get("timestamp_utc") or ""
        existing = grouped.setdefault(
            ip,
            {
                "source_ip": ip,
                "count": 0,
                "attack_count": 0,
                "normal_count": 0,
                "route_count": 0,
                "protocols": set(),
                "risk_level": risk,
                "risk_rank": risk_rank(risk),
                "predicted_attack": derive_attack_label(event, prediction),
                "last_seen": timestamp,
                **deterministic_geo(ip),
            },
        )
        existing["count"] += 1
        if is_attack:
            existing["attack_count"] += 1
        else:
            existing["normal_count"] += 1
        existing["protocols"].add(str(event.get("protocol") or "unknown").lower())
        if timestamp and timestamp > str(existing.get("last_seen") or ""):
            existing["last_seen"] = timestamp
        if risk_rank(risk) > existing["risk_rank"]:
            existing["risk_level"] = risk
            existing["risk_rank"] = risk_rank(risk)
            existing["predicted_attack"] = derive_attack_label(event, prediction)

    attack_items = []
    normal_items = []
    for item in grouped.values():
        item["protocols"] = sorted(item["protocols"])
        if item["attack_count"] > 0:
            attack_items.append(item)
        else:
            normal_items.append(item)

    attack_limit = max(1, int(MAX_MAP_POINTS * 0.7))
    normal_limit = max(1, MAX_MAP_POINTS - attack_limit)
    attack_items.sort(key=lambda row: (row["risk_rank"], row["attack_count"], row["count"], row["last_seen"]), reverse=True)
    normal_items.sort(key=lambda row: (row["count"], row["last_seen"]), reverse=True)
    return [*attack_items[:attack_limit], *normal_items[:normal_limit]]


def build_top_sources(packets: list[dict[str, Any]], limit: int = 80) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for packet in packets:
        ip = normalize_ip(packet.get("source_ip"))
        if ip == "unknown":
            continue

        timestamp = packet.get("timestamp_utc") or ""
        risk = str(packet.get("risk_level") or "Low")
        route = str(packet.get("route_decision") or packet.get("routed_to") or "").lower()
        route_label = "honeypot" if "honeypot" in route or packet_is_attack(packet) else "real"
        item = grouped.setdefault(
            ip,
            {
                "source_ip": ip,
                "count": 0,
                "attack_count": 0,
                "normal_count": 0,
                "route_count": 0,
                "protocols": set(),
                "risk_level": risk,
                "risk_rank": risk_rank(risk),
                "predicted_attack": packet.get("predicted_attack") or "Observed_Activity",
                "route_decision": route_label,
                "routed_to": route_label,
                "score": packet.get("score"),
                "first_seen": timestamp,
                "last_seen": timestamp,
                **deterministic_geo(ip),
            },
        )

        item["count"] += 1
        if str(packet.get("event_type") or "").lower() == "router_decision" or str(packet.get("log_origin") or "").lower() == "routing_decisions":
            item["route_count"] += 1
        if packet_is_attack(packet):
            item["attack_count"] += 1
        else:
            item["normal_count"] += 1
        item["protocols"].add(str(packet.get("protocol") or "unknown").lower())

        if timestamp:
            if not item["first_seen"] or timestamp < item["first_seen"]:
                item["first_seen"] = timestamp
            if not item["last_seen"] or timestamp > item["last_seen"]:
                item["last_seen"] = timestamp
                item["route_decision"] = route_label
                item["routed_to"] = route_label
                item["score"] = packet.get("score")
                item["predicted_attack"] = packet.get("predicted_attack") or item["predicted_attack"]

        if risk_rank(risk) > item["risk_rank"]:
            item["risk_level"] = risk
            item["risk_rank"] = risk_rank(risk)
            item["predicted_attack"] = packet.get("predicted_attack") or item["predicted_attack"]

    output = []
    for item in grouped.values():
        item["protocols"] = sorted(item["protocols"])
        output.append(item)
    output.sort(key=lambda row: (row["count"], row["attack_count"], row["last_seen"]), reverse=True)
    return output[:limit]


def _load_dataset_uncached() -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], list[dict[str, Any]]]:
    events = read_jsonl_tail(UNIFIED_PATH, MAX_EVENTS)
    routes = read_jsonl_tail(ROUTING_PATH, MAX_ROUTES)
    predictions = latest_predictions(read_jsonl_tail(PREDICTIONS_PATH, MAX_PREDICTIONS))
    return events, predictions, routes


def load_dataset() -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], list[dict[str, Any]]]:
    """Return the parsed dataset, reusing a recent cached parse when possible.

    Callers only read the returned structures (they build new lists/dicts from
    them), so sharing one parse across concurrent requests is safe. A short TTL
    plus a file-signature check keeps the data live while collapsing the
    repeated multi-MB reparse that was saturating the single uvicorn worker.
    """
    global DATASET_CACHE, DATASET_SIGNATURE, DATASET_GENERATED_MONOTONIC
    now = monotonic()
    with DATASET_CACHE_LOCK:
        if DATASET_CACHE is not None and (now - DATASET_GENERATED_MONOTONIC) < DATASET_MAX_AGE_SECONDS:
            return DATASET_CACHE
        current_signature = dataset_signature()
        if DATASET_CACHE is not None and DATASET_SIGNATURE == current_signature:
            DATASET_GENERATED_MONOTONIC = now
            return DATASET_CACHE

        dataset = _load_dataset_uncached()
        DATASET_CACHE = dataset
        DATASET_SIGNATURE = dataset_signature()
        DATASET_GENERATED_MONOTONIC = monotonic()
        return DATASET_CACHE


def build_snapshot() -> dict[str, Any]:
    events, predictions, routes = load_dataset()
    summarized = [event_summary(event, predictions) for event in events]
    summarized.sort(key=lambda row: row.get("timestamp_utc") or "", reverse=True)
    all_packets = dedupe_packets(summarized)
    packets = all_packets[:WINDOW_PACKETS]

    alerts = [
        row for row in packets
        if packet_is_attack(row) and (
            row["risk_level"].lower() in {"critical", "high"} or str(row.get("route_decision")).lower() == "honeypot"
        )
    ][:80]

    unique_ips = {row["source_ip"] for row in packets if row["source_ip"] != "unknown"}
    total_unique_ips = {row["source_ip"] for row in all_packets if row["source_ip"] != "unknown"}
    prediction_rows = list(predictions.values())
    attack_counts = Counter(attack_category(row.get("predicted_attack")) for row in packets)
    attacked_count = sum(1 for row in packets if packet_is_attack(row))
    normal_count = len(packets) - attacked_count
    total_attacked_count = sum(1 for row in all_packets if packet_is_attack(row))
    total_normal_count = len(all_packets) - total_attacked_count
    high_count = sum(1 for row in packets if packet_is_attack(row) and risk_rank(str(row.get("risk_level"))) >= 3)
    critical_count = sum(1 for row in packets if row["risk_level"].lower() == "critical")
    lifetime_honey, lifetime_real = count_route_split_from_start()
    lifetime_unique_ips = count_unique_sources_from_start()
    protocol_dashboards = build_protocol_dashboards(packets)

    return {
        "generated_at": utc_now(),
        "data_sources": {
            "unified_events": str(UNIFIED_PATH),
            "predictions": str(PREDICTIONS_PATH),
            "routing_decisions": str(ROUTING_PATH),
        },
        "summary": {
            "events_loaded": len(events),
            "total_events_from_start": count_lines_cached(UNIFIED_PATH),
            "total_raw_events_from_start": count_raw_events_from_start(),
            "packets_loaded": len(packets),
            "window_packets": len(packets),
            "window_packet_limit": WINDOW_PACKETS,
            "total_events_system": len(events),
            "total_packets_system": len(all_packets),
            "total_attacked_packets_system": total_attacked_count,
            "total_normal_packets_system": total_normal_count,
            "total_attacked_from_start": lifetime_honey,
            "total_normal_from_start": lifetime_real,
            "total_unique_ips_system": len(total_unique_ips),
            "total_unique_ips_from_start": lifetime_unique_ips,
            "unique_ips": len(unique_ips),
            "predictions": len(prediction_rows),
            "attacked_packets": attacked_count,
            "normal_packets": normal_count,
            "high_alerts": high_count,
            "critical_events": critical_count,
            "last_event_at": packets[0]["timestamp_utc"] if packets else None,
        },
        "recent_events": summarized[:RECENT_LIMIT],
        "recent_packets": packets[:RECENT_LIMIT],
        "alerts": alerts,
        "protocol_dashboards": protocol_dashboards,
        "protocol_breakdown": protocol_breakdown_from_dashboards(protocol_dashboards),
        "attack_breakdown": [{"name": key, "value": value} for key, value in attack_counts.most_common()],
        "top_sources": build_top_sources(all_packets),
        "heatmap": build_heatmap(packets, predictions),
        "attack_map": build_attack_map(packets, predictions),
        "latest_routes": sorted(routes, key=event_timestamp_key, reverse=True)[:120],
    }


def get_snapshot_cached(force: bool = False) -> dict[str, Any]:
    global SNAPSHOT_CACHE, SNAPSHOT_SIGNATURE, SNAPSHOT_GENERATED_MONOTONIC
    now = monotonic()
    current_signature = dataset_signature()
    with SNAPSHOT_CACHE_LOCK:
        if not force and SNAPSHOT_CACHE is not None and (now - SNAPSHOT_GENERATED_MONOTONIC) < SNAPSHOT_MAX_AGE_SECONDS:
            return SNAPSHOT_CACHE
        if not force and SNAPSHOT_CACHE is not None and SNAPSHOT_SIGNATURE == current_signature:
            return SNAPSHOT_CACHE

        snapshot = build_snapshot()
        refreshed_signature = dataset_signature()
        SNAPSHOT_CACHE = snapshot
        SNAPSHOT_SIGNATURE = refreshed_signature
        SNAPSHOT_GENERATED_MONOTONIC = monotonic()
        return SNAPSHOT_CACHE


def ip_details(source_ip: str) -> dict[str, Any]:
    events, predictions, routes = load_dataset()
    ip = normalize_ip(source_ip)
    matched_events = [event for event in events if normalize_ip(event.get("source_ip")) == ip]
    matched_routes = [route for route in routes if normalize_ip(route.get("source_ip")) == ip]
    prediction = predictions.get(ip)
    matched_events.sort(key=event_timestamp_key, reverse=True)
    matched_routes.sort(key=event_timestamp_key, reverse=True)

    # Fall back to the route decision carried on each event when this IP has no
    # dedicated routing_decisions.jsonl rows (log-bridge protocols like SSH/RTSP
    # don't always emit separate decision records). This keeps the Decision
    # History and Last Action populated for every packet instead of showing n/a.
    if not matched_routes:
        matched_routes = [
            {
                "decision_id": event.get("decision_id"),
                "timestamp_utc": event.get("timestamp_utc"),
                "source_ip": ip,
                "protocol": str(event.get("protocol") or "unknown").lower(),
                "route_decision": event.get("route_decision"),
                "routed_to": event.get("routed_to"),
                "score": event.get("router_score", event.get("score")),
                "reason": event.get("reason"),
            }
            for event in matched_events
            if event.get("route_decision")
        ]
        matched_routes.sort(key=event_timestamp_key, reverse=True)

    returned_events = matched_events[:MAX_IP_DETAILS]
    returned_routes = matched_routes[:MAX_IP_DETAILS]
    latest_event = event_summary(matched_events[0], predictions) if matched_events else None
    latest_route = matched_routes[0] if matched_routes else None
    fallback_event = latest_event or latest_route or {}
    fallback_prediction = prediction or None
    risk_level = (prediction or {}).get("risk_level") or infer_risk(fallback_event, fallback_prediction)
    predicted_attack = derive_attack_label(fallback_event, fallback_prediction)

    return {
        "source_ip": ip,
        "prediction": prediction,
        "events": returned_events,
        "routes": returned_routes,
        "summary": {
            "event_count": len(matched_events),
            "route_count": len(matched_routes),
            "events_returned": len(returned_events),
            "routes_returned": len(returned_routes),
            "events_truncated": len(returned_events) < len(matched_events),
            "routes_truncated": len(returned_routes) < len(matched_routes),
            "protocols": sorted({str(event.get("protocol") or "unknown").lower() for event in matched_events}),
            "risk_level": risk_level,
            "predicted_attack": predicted_attack,
            "first_seen": min((event.get("timestamp_utc") for event in matched_events if event.get("timestamp_utc")), default=None),
            "last_seen": max((event.get("timestamp_utc") for event in matched_events if event.get("timestamp_utc")), default=None),
            "last_event_type": latest_event.get("event_type") if latest_event else None,
            "last_event_at": latest_event.get("timestamp_utc") if latest_event else None,
            "last_route_decision": latest_route.get("route_decision") if latest_route else None,
            "last_routed_to": latest_route.get("routed_to") if latest_route else None,
            "last_route_at": latest_route.get("timestamp_utc") if latest_route else None,
        },
    }


def escape_pdf_text(text: Any) -> str:
    value = str(text if text is not None else "")
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def simple_pdf(title: str, lines: list[str]) -> bytes:
    lines_per_page = 42
    pages = [lines[index:index + lines_per_page] for index in range(0, len(lines), lines_per_page)] or [[]]
    page_count = len(pages)
    font_id = 3 + page_count
    content_start_id = font_id + 1
    kids = " ".join(f"{3 + index} 0 R" for index in range(page_count))

    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        f"<< /Type /Pages /Kids [{kids}] /Count {page_count} >>".encode(),
    ]

    for index in range(page_count):
        content_id = content_start_id + index
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] "
            f"/Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>"
            .encode()
        )

    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    for page_index, page_lines in enumerate(pages, start=1):
        content_lines = [
            "BT",
            "/F1 14 Tf",
            "50 790 Td",
            f"({escape_pdf_text(title[:100])}) Tj",
            "/F1 8 Tf",
            "0 -14 Td",
            f"(Page {page_index} of {page_count}) Tj",
            "/F1 9 Tf",
        ]
        for line in page_lines:
            content_lines.append("0 -16 Td")
            content_lines.append(f"({escape_pdf_text(line[:120])}) Tj")
        content_lines.append("ET")
        stream = "\n".join(content_lines).encode("latin-1", errors="replace")
        objects.append(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream")

    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode())
        output.extend(obj)
        output.extend(b"\nendobj\n")

    xref_offset = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode()
    )
    return bytes(output)


app = FastAPI(title="IoT Honeypot SOC Dashboard", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def warm_snapshot_cache() -> None:
    # Do not block uvicorn from binding the dashboard port while large JSONL
    # snapshots are rebuilt. Requests and websockets refresh the cache on demand.
    return None


@app.post("/api/auth/token")
def auth_token(body: dict[str, Any]) -> dict[str, Any]:
    if not _AUTH_ENABLED:
        return {"token": "", "auth_required": False}
    password = str(body.get("password") or "")
    token = hashlib.sha256(password.encode()).hexdigest()
    if not secrets.compare_digest(token, _AUTH_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid password")
    return {"token": token, "auth_required": True}


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "generated_at": utc_now(),
        "auth_required": _AUTH_ENABLED,
        "unified_exists": UNIFIED_PATH.exists(),
        "predictions_exists": PREDICTIONS_PATH.exists(),
        "routing_exists": ROUTING_PATH.exists(),
    }


@app.get("/api/summary")
def api_summary(_: None = Depends(verify_auth)) -> dict[str, Any]:
    return get_snapshot_cached()


@app.get("/api/events")
def api_events(limit: int = 200, _: None = Depends(verify_auth)) -> dict[str, Any]:
    events, predictions, _routes = load_dataset()
    summarized = [event_summary(event, predictions) for event in events]
    summarized.sort(key=lambda row: row.get("timestamp_utc") or "", reverse=True)
    return {"events": summarized[: max(1, min(limit, 500))]}


@app.get("/api/alerts")
def api_alerts(_: None = Depends(verify_auth)) -> dict[str, Any]:
    snapshot = get_snapshot_cached()
    return {"alerts": snapshot["alerts"]}


@app.get("/api/predictions")
def api_predictions(limit: int = 100, _: None = Depends(verify_auth)) -> dict[str, Any]:
    _events, predictions, _routes = load_dataset()
    rows = list(predictions.values())
    risk_order = {"high": 0, "medium": 1, "low": 2, "none": 3}
    rows.sort(key=lambda r: (
        risk_order.get(str(r.get("risk_level") or "").lower(), 4),
        -float(r.get("confidence") or 0),
    ))
    return {"predictions": rows[: max(1, min(limit, 500))]}


@app.get("/api/paths")
def api_paths(limit: int = 100, _: None = Depends(verify_auth)) -> dict[str, Any]:
    routes_raw = read_jsonl_tail(ROUTING_PATH, MAX_PATHS_SCAN)
    path_stats: dict[str, dict[str, Any]] = {}
    for route in routes_raw:
        path = str(route.get("path") or "").strip()
        if not path or str(route.get("protocol") or "").lower() not in ("http", "https"):
            continue
        stats = path_stats.setdefault(path, {
            "path": path, "hits": 0, "honeypot": 0, "real": 0,
            "top_score": 0, "reasons": Counter(),
        })
        stats["hits"] += 1
        decision = str(route.get("route_decision") or "")
        if decision == "honeypot":
            stats["honeypot"] += 1
        elif decision == "real":
            stats["real"] += 1
        score = safe_int(route.get("score"))
        if score > stats["top_score"]:
            stats["top_score"] = score
        for reason in (route.get("reason") or []):
            stats["reasons"][str(reason)] += 1

    result = []
    for stats in path_stats.values():
        hits = stats["hits"]
        result.append({
            "path": stats["path"],
            "hits": hits,
            "honeypot": stats["honeypot"],
            "real": stats["real"],
            "honeypot_pct": round(stats["honeypot"] / hits * 100, 1) if hits else 0,
            "top_score": stats["top_score"],
            "top_reasons": [r for r, _ in stats["reasons"].most_common(3)],
        })
    result.sort(key=lambda x: x["hits"], reverse=True)
    return {"paths": result[: max(1, min(limit, 500))], "total_paths": len(result)}


@app.get("/api/honeypot/responses")
def api_honeypot_responses(limit: int = 50, ip: str = "", _: None = Depends(verify_auth)) -> dict[str, Any]:
    rows = read_jsonl_tail(HONEYPOT_LOG_PATH, 5000) if HONEYPOT_LOG_PATH.exists() else []
    if ip:
        normalized = normalize_ip(ip)
        rows = [r for r in rows if normalize_ip(r.get("ip", "")) == normalized]
    rows.sort(key=lambda r: str(r.get("timestamp_utc") or ""), reverse=True)
    result = []
    for row in rows[: max(1, min(limit, 200))]:
        body = str(row.get("body") or "")
        result.append({
            "timestamp_utc": row.get("timestamp_utc"),
            "ip": row.get("ip"),
            "method": row.get("method"),
            "path": row.get("path"),
            "response_status": row.get("response_status"),
            "user_agent": str(row.get("user_agent") or "")[:120],
            "body_preview": body[:400] if body else None,
            "content_type": row.get("content_type"),
        })
    return {"responses": result, "total": len(rows)}


@app.get("/api/ip/{source_ip:path}")
def api_ip(source_ip: str, _: None = Depends(verify_auth)) -> dict[str, Any]:
    return ip_details(source_ip)


@app.get("/api/export/session/{source_ip:path}")
def export_session(source_ip: str, _: None = Depends(verify_auth)) -> Response:
    details = ip_details(source_ip)
    summary = details["summary"]
    prediction = details.get("prediction") or {}
    lines = [
        f"Generated UTC: {utc_now()}",
        f"Source IP: {details['source_ip']}",
        f"Risk Level: {summary.get('risk_level')}",
        f"Predicted Attack: {summary.get('predicted_attack')}",
        f"Confidence: {prediction.get('confidence', 'n/a')}",
        f"Event Count: {summary.get('event_count')}",
        f"Route Decision Count: {summary.get('route_count')}",
        f"Events Included In Export: {summary.get('events_returned')}",
        f"Routes Included In Export: {summary.get('routes_returned')}",
        f"Protocols: {', '.join(summary.get('protocols') or [])}",
        f"First Seen: {summary.get('first_seen')}",
        f"Last Seen: {summary.get('last_seen')}",
        f"Last Router Station: {summary.get('last_route_decision')} -> {summary.get('last_routed_to')} at {summary.get('last_route_at')}",
        f"Last Event: {summary.get('last_event_type')} at {summary.get('last_event_at')}",
        "",
        "All router decisions available to dashboard:",
    ]
    if summary.get("routes_truncated"):
        lines.append(f"NOTE: route export truncated at {summary.get('routes_returned')} rows.")
    for route in details["routes"]:
        lines.append(
            f"- {route.get('timestamp_utc')} {route.get('protocol')} {route.get('route_decision')} "
            f"to={route.get('routed_to')} backend={route.get('backend_port')} score={route.get('score')} "
            f"path={route.get('path')} topic={route.get('topic')} reason={route.get('reason')}"
        )
    lines.append("")
    lines.append("All events available to dashboard:")
    if summary.get("events_truncated"):
        lines.append(f"NOTE: event export truncated at {summary.get('events_returned')} rows.")
    for event in details["events"]:
        lines.append(
            f"- {event.get('timestamp_utc')} {event.get('protocol')} {event.get('event_type')} "
            f"route={event.get('route_decision')} to={event.get('routed_to')} "
            f"path={event.get('path')} topic={event.get('topic')} payload={event.get('payload')}"
        )

    pdf = simple_pdf(f"IoT Honeypot Attack Session: {details['source_ip']}", lines)
    filename = f"attack-session-{details['source_ip'].replace('.', '-')}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket) -> None:
    await websocket.accept()
    try:
        while True:
            snapshot = await asyncio.to_thread(get_snapshot_cached)
            await websocket.send_json({"type": "snapshot", "payload": snapshot})
            await asyncio.sleep(WS_SNAPSHOT_INTERVAL_SECONDS)
    except WebSocketDisconnect:
        return


