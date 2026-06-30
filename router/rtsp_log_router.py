#!/usr/bin/env python3
"""
Router-owned RTSP log decision bridge.

MediaMTX already receives public RTSP traffic on port 554. This bridge reads
new MediaMTX log lines, creates router events, writes first-decision records,
and produces RTSP router events for normalization and ML.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


ROUTER_DIR = Path(__file__).resolve().parent
if str(ROUTER_DIR) not in sys.path:
    sys.path.insert(0, str(ROUTER_DIR))

from session_router import SessionRouter  # noqa: E402


BASE = Path("/opt/iot-honeypot")
DEFAULT_INPUT = BASE / "rtsp" / "logs" / "mediamtx.log"
DEFAULT_OUTPUT = BASE / "logs" / "rtsp_router_events.jsonl"
DEFAULT_STATE = ROUTER_DIR / "rtsp_log_router_state.json"


TIMESTAMP_RE = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")
SOURCE_RE = re.compile(r"\[(?:RTSP)\] \[(?:conn|session) ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+)\]")
CONNECTION_RE = re.compile(r"\[(RTSP)\] \[((?:conn|session) [^\]]+)\]")
PATH_RE = re.compile(r"(?:path|from path) '([^']+)'")
TEST_ID_RE = re.compile(r"(rtsp-loopback-[A-Za-z0-9_.-]+)")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_mediamtx_timestamp(value: str | None) -> str:
    if not value:
        return utc_now()
    try:
        parsed = datetime.strptime(value, "%Y/%m/%d %H:%M:%S")
        return parsed.replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return utc_now()


def load_state(path: Path) -> dict:
    if not path.exists():
        return {"processed_hashes": []}
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"processed_hashes": []}
    if not isinstance(state, dict):
        return {"processed_hashes": []}
    state.setdefault("processed_hashes", [])
    return state


def save_state(path: Path, processed_hashes: deque[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "updated_at": utc_now(),
                "processed_hashes": list(processed_hashes),
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def read_tail(path: Path, max_lines: int) -> list[str]:
    if not path.exists():
        return []
    if max_lines > 0:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            return list(deque(handle, maxlen=max_lines))
    return path.read_text(encoding="utf-8", errors="ignore").splitlines()


def line_hash(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8", errors="ignore")).hexdigest()


def infer_event_type(line: str) -> str:
    if " opened" in line:
        return "connection_opened"
    if " closed:" in line:
        return "connection_closed"
    if "is reading from path" in line:
        return "stream_read"
    if "created by" in line:
        return "session_created"
    if "destroyed:" in line:
        return "session_destroyed"
    if "is publishing to path" in line:
        return "stream_publish"
    return "connection"


def extract_close_reason(line: str) -> str | None:
    if " closed:" not in line:
        return None
    return line.split(" closed:", 1)[1].strip() or None


def parse_line(line: str) -> dict | None:
    if "[RTSP]" not in line or ("[conn" not in line and "[session" not in line):
        return None

    source_match = SOURCE_RE.search(line)
    if not source_match:
        return None

    timestamp_match = TIMESTAMP_RE.search(line)
    connection_match = CONNECTION_RE.search(line)
    path_match = PATH_RE.search(line)
    test_id_match = TEST_ID_RE.search(line)

    return {
        "timestamp_utc": parse_mediamtx_timestamp(timestamp_match.group(1) if timestamp_match else None),
        "source_ip": source_match.group(1),
        "source_port": int(source_match.group(2)),
        "protocol": "rtsp",
        "event_type": infer_event_type(line),
        "destination_port": 554,
        "path": path_match.group(1) if path_match else None,
        "close_reason": extract_close_reason(line),
        "payload": line.strip(),
        "connection_id": connection_match.group(2) if connection_match else f"rtsp-{uuid4()}",
        "test_id": test_id_match.group(1) if test_id_match else None,
    }


def append_jsonl(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def route_line(router: SessionRouter, event: dict, output_path: Path) -> dict:
    decision = router.decide(dict(event))
    record = {
        "timestamp_utc": event["timestamp_utc"],
        "source_ip": event["source_ip"],
        "source_port": event["source_port"],
        "protocol": "rtsp",
        "event_type": event["event_type"],
        "destination_port": 554,
        "path": event.get("path"),
        "close_reason": event.get("close_reason"),
        "payload": event.get("payload"),
        "connection_id": event.get("connection_id"),
        "test_id": event.get("test_id"),
        "route_decision": decision.get("route_decision"),
        "route_label": decision.get("route_label"),
        "routed_to": decision.get("routed_to"),
        "backend_port": decision.get("backend_port"),
        "log_bucket": decision.get("log_bucket"),
        "decision_stage": decision.get("decision_stage"),
        "decision_id": decision.get("decision_id"),
        "score": decision.get("score"),
        "reason": decision.get("reason"),
    }
    append_jsonl(output_path, record)
    return record


def process_once(args) -> int:
    state = load_state(args.state_path)
    processed = deque(state.get("processed_hashes", []), maxlen=args.state_size)
    processed_set = set(processed)
    router = SessionRouter(cache_path=str(args.cache_path))

    routed_count = 0
    for raw_line in read_tail(args.input_path, args.max_lines):
        line = raw_line.rstrip("\n")
        digest = line_hash(line)
        if digest in processed_set:
            continue

        event = parse_line(line)
        processed.append(digest)
        processed_set.add(digest)
        if not event:
            continue

        route_line(router, event, args.output_path)
        routed_count += 1

    save_state(args.state_path, processed)
    return routed_count


def main() -> None:
    parser = argparse.ArgumentParser(description="Route RTSP MediaMTX log lines into router decisions")
    parser.add_argument("--input", dest="input_path", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", dest="output_path", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--state", dest="state_path", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--cache-path", type=Path, default=ROUTER_DIR / "state_cache.json")
    parser.add_argument("--max-lines", type=int, default=5000)
    parser.add_argument("--state-size", type=int, default=20000)
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--interval", type=float, default=2.0)
    args = parser.parse_args()

    while True:
        count = process_once(args)
        print(f"[{utc_now()}] routed {count} RTSP log lines", flush=True)
        if not args.watch:
            return
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
