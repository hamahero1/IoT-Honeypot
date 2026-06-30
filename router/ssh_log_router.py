#!/usr/bin/env python3
"""
Router-owned SSH log decision bridge.

Cowrie already receives public SSH traffic. This bridge reads new Cowrie JSON
events, creates router decisions, writes first-decision records, and produces
SSH router-side events for monitoring and analysis.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path


ROUTER_DIR = Path(__file__).resolve().parent
if str(ROUTER_DIR) not in sys.path:
    sys.path.insert(0, str(ROUTER_DIR))

from session_router import SessionRouter  # noqa: E402


BASE = Path("/opt/iot-honeypot")
COWRIE_DIR = BASE / "logs" / "cowrie"
DEFAULT_OUTPUT = BASE / "logs" / "ssh_router_events.jsonl"
DEFAULT_STATE = ROUTER_DIR / "ssh_log_router_state.json"

EVENT_MAP = {
    "cowrie.session.connect": "connection_opened",
    "cowrie.session.closed": "connection_closed",
    "cowrie.login.failed": "login_attempt",
    "cowrie.login.success": "login_success",
    "cowrie.command.input": "command_executed",
    "cowrie.session.file_download": "file_download",
    "cowrie.session.file_upload": "file_upload",
    "cowrie.client.kex": "client_fingerprint",
    "cowrie.client.version": "client_version",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def line_hash(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8", errors="ignore")).hexdigest()


def iter_cowrie_paths(max_files: int) -> list[Path]:
    if not COWRIE_DIR.exists():
        return []

    ssh_paths = [
        path for path in sorted(COWRIE_DIR.glob("cowrie.json*"))
        if not path.name.endswith(".log")
    ]

    if max_files > 0:
        current_paths = [path for path in ssh_paths if path.name == "cowrie.json"]
        rotated_paths = [path for path in ssh_paths if path.name != "cowrie.json"]
        keep_rotated = max(max_files - len(current_paths), 0)
        ssh_paths = rotated_paths[-keep_rotated:] + current_paths

    return ssh_paths


def iter_recent_lines(path: Path, max_lines: int):
    if max_lines > 0:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in deque(handle, maxlen=max_lines):
                yield line.rstrip("\n")
        return

    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            yield line.rstrip("\n")


def parse_line(line: str) -> dict | None:
    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        return None

    source_ip = raw.get("src_ip")
    if not source_ip:
        return None

    eventid = str(raw.get("eventid") or "").strip()
    event_type = EVENT_MAP.get(eventid, eventid.replace("cowrie.", "").replace(".", "_") or "ssh_event")
    payload = raw.get("message")
    command = raw.get("input") or raw.get("command") or raw.get("cmd")

    return {
        "timestamp_utc": raw.get("timestamp"),
        "source_ip": source_ip,
        "source_port": raw.get("src_port"),
        "protocol": "ssh",
        "event_type": event_type,
        "destination_port": 22,
        "username": raw.get("username"),
        "password": raw.get("password"),
        "command": command,
        "payload": payload,
        "connection_id": raw.get("session"),
        "raw_eventid": eventid,
        "raw_uuid": raw.get("uuid"),
        "raw_version": raw.get("version"),
        "raw_hassh": raw.get("hassh"),
    }


def append_jsonl(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def route_event(router: SessionRouter, event: dict, output_path: Path) -> dict:
    decision = router.decide(dict(event))
    record = {
        "timestamp_utc": event["timestamp_utc"],
        "source_ip": event["source_ip"],
        "source_port": event.get("source_port"),
        "protocol": "ssh",
        "event_type": event["event_type"],
        "destination_port": 22,
        "username": event.get("username"),
        "password": event.get("password"),
        "command": event.get("command"),
        "payload": event.get("payload"),
        "connection_id": event.get("connection_id"),
        "raw_eventid": event.get("raw_eventid"),
        "raw_uuid": event.get("raw_uuid"),
        "raw_version": event.get("raw_version"),
        "raw_hassh": event.get("raw_hassh"),
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
    for path in iter_cowrie_paths(args.max_files):
        for line in iter_recent_lines(path, args.max_lines):
            digest = line_hash(line)
            if digest in processed_set:
                continue

            processed.append(digest)
            processed_set.add(digest)
            event = parse_line(line)
            if not event:
                continue

            route_event(router, event, args.output_path)
            routed_count += 1

    save_state(args.state_path, processed)
    return routed_count


def main() -> None:
    parser = argparse.ArgumentParser(description="Route Cowrie SSH log lines into router decisions")
    parser.add_argument("--output", dest="output_path", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--state", dest="state_path", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--cache-path", type=Path, default=ROUTER_DIR / "state_cache.json")
    parser.add_argument("--max-lines", type=int, default=5000)
    parser.add_argument("--max-files", type=int, default=7)
    parser.add_argument("--state-size", type=int, default=50000)
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--interval", type=float, default=2.0)
    args = parser.parse_args()

    while True:
        count = process_once(args)
        print(f"[{utc_now()}] routed {count} SSH log lines", flush=True)
        if not args.watch:
            return
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
