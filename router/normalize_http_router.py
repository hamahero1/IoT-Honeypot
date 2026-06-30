#!/usr/bin/env python3
"""
Router-owned HTTP normalizer.

Edit summary:
- This is a new HTTP-only normalizer kept in /router for testing before changing
  the main project pipeline.
- It keeps the old normalized HTTP fields:
  timestamp_utc, source_ip, protocol, event_type, username, password,
  command, payload, response_status
- It adds router metadata from routing and ingress logs so the next ML step can
  use route, score, reason, session, and backend information.
- Default output is a test file in /router, so unified_events.jsonl is not
  touched by this script.
"""

import argparse
import json
from pathlib import Path


BASE = Path("/opt/iot-honeypot")
ROUTING_INPUT = BASE / "logs" / "routing_decisions.jsonl"
INGRESS_INPUT = BASE / "logs" / "http_ingress_80.jsonl"
HONEYPOT_INPUT = BASE / "logs" / "http_honeypot.jsonl"
REAL_INPUT = BASE / "logs" / "http_real_28080.jsonl"
DEFAULT_OUTPUT = BASE / "router" / "http_normalized_router_test.jsonl"


def add_event(events, seen, event):
    line = json.dumps(event, ensure_ascii=False, sort_keys=True)
    if line not in seen:
        seen.add(line)
        events.append(event)


def iter_jsonl(path, limit=0):
    if not path.exists():
        return

    count = 0
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue

            yield row
            count += 1
            if limit and count >= limit:
                break


def route_label_from_decision(route_decision):
    if route_decision == "honeypot":
        return 1
    if route_decision == "real":
        return 0
    return None


def first_source_ip(value):
    text = str(value or "").strip()
    if "," in text:
        return text.split(",", 1)[0].strip()
    return text or None


def build_base_http_event(
    *,
    timestamp_utc,
    source_ip,
    event_type,
    payload,
    response_status,
    username=None,
    password=None,
):
    return {
        "timestamp_utc": timestamp_utc,
        "source_ip": first_source_ip(source_ip),
        "protocol": "http",
        "event_type": event_type,
        "username": username,
        "password": password,
        "command": None,
        "payload": payload,
        "response_status": response_status,
    }


def attach_router_fields(
    event,
    *,
    log_origin,
    path=None,
    method=None,
    query_string=None,
    user_agent=None,
    route_decision=None,
    route_label=None,
    score=None,
    reason=None,
    routed_to=None,
    backend_port=None,
    decision_stage=None,
    log_bucket=None,
    decision_id=None,
    request_id=None,
    session_id=None,
):
    # Router edit: preserve the old HTTP normalized shape and add router-aware
    # metadata for later ML integration.
    event["log_origin"] = log_origin
    event["path"] = path
    event["method"] = method
    event["query_string"] = query_string
    event["user_agent"] = user_agent
    event["route_decision"] = route_decision
    event["route_label"] = route_label
    event["score"] = score
    event["router_score"] = score
    event["reason"] = reason
    event["router_reason"] = reason
    event["routed_to"] = routed_to
    event["backend_port"] = backend_port
    event["decision_stage"] = decision_stage
    event["log_bucket"] = log_bucket
    event["decision_id"] = decision_id
    event["request_id"] = request_id
    event["session_id"] = session_id
    return event


def load_routing_decisions(events, seen, limit=0):
    for row in iter_jsonl(ROUTING_INPUT, limit=limit):
        normalized_event = build_base_http_event(
            timestamp_utc=row.get("timestamp_utc"),
            source_ip=row.get("source_ip"),
            event_type="router_decision",
            payload=row.get("path"),
            response_status=None,
        )
        attach_router_fields(
            normalized_event,
            log_origin="routing_decisions",
            path=row.get("path"),
            route_decision=row.get("route_decision"),
            route_label=row.get("route_label", route_label_from_decision(row.get("route_decision"))),
            score=row.get("score"),
            reason=row.get("reason"),
            routed_to=row.get("routed_to"),
            backend_port=row.get("backend_port"),
            decision_stage=row.get("decision_stage"),
            log_bucket=row.get("log_bucket"),
            decision_id=row.get("decision_id"),
            request_id=row.get("request_id"),
            session_id=row.get("session_id"),
        )
        add_event(events, seen, normalized_event)


def load_ingress(events, seen, limit=0):
    for row in iter_jsonl(INGRESS_INPUT, limit=limit):
        route_decision = row.get("route_decision")
        normalized_event = build_base_http_event(
            timestamp_utc=row.get("timestamp_utc"),
            source_ip=row.get("source_ip"),
            event_type=row.get("event_type", "ingress_request"),
            payload=row.get("payload"),
            response_status=row.get("response_status"),
        )
        attach_router_fields(
            normalized_event,
            log_origin="http_ingress_80",
            path=row.get("path"),
            method=row.get("method"),
            query_string=row.get("query_string"),
            user_agent=row.get("user_agent"),
            route_decision=route_decision,
            route_label=route_label_from_decision(route_decision),
            score=row.get("decision_score"),
            reason=row.get("decision_reason"),
            routed_to=row.get("routed_to"),
            backend_port=row.get("backend_port"),
            decision_stage="first_decision",
            log_bucket=row.get("log_bucket"),
            decision_id=row.get("decision_id"),
            request_id=row.get("request_id"),
            session_id=row.get("session_id"),
        )
        add_event(events, seen, normalized_event)


def load_honeypot(events, seen, limit=0):
    for row in iter_jsonl(HONEYPOT_INPUT, limit=limit):
        extra = row.get("extra") or {}
        headers = row.get("headers") or {}
        username = row.get("username") or extra.get("username")
        password = row.get("password") or extra.get("password")
        route_decision = headers.get("X-Route-Decision") or "honeypot"

        normalized_event = build_base_http_event(
            timestamp_utc=row.get("timestamp_utc"),
            source_ip=row.get("ip"),
            event_type="login_attempt" if (username or password) else "http_request",
            payload=row.get("body"),
            response_status=row.get("response_status"),
            username=username,
            password=password,
        )
        attach_router_fields(
            normalized_event,
            log_origin="http_honeypot",
            path=row.get("path"),
            method=row.get("method"),
            query_string=row.get("query_string"),
            user_agent=row.get("user_agent"),
            route_decision=route_decision,
            route_label=route_label_from_decision(route_decision),
            score=None,
            reason=None,
            routed_to=headers.get("X-Routed-To") or "http_honeypot",
            backend_port=8080,
            decision_stage="backend_observation",
            log_bucket="honeypot_logs",
            decision_id=headers.get("X-Decision-Id"),
            request_id=headers.get("X-Request-Id"),
            session_id=headers.get("X-Session-Id"),
        )
        add_event(events, seen, normalized_event)


def load_real_backend(events, seen, limit=0):
    for row in iter_jsonl(REAL_INPUT, limit=limit):
        normalized_event = build_base_http_event(
            timestamp_utc=row.get("timestamp_utc"),
            source_ip=row.get("source_ip"),
            event_type="http_request",
            payload=row.get("path"),
            response_status=row.get("status_code"),
        )
        attach_router_fields(
            normalized_event,
            log_origin="http_real_28080",
            path=row.get("path"),
            method=row.get("method"),
            user_agent=row.get("user_agent"),
            route_decision="real",
            route_label=0,
            score=None,
            reason=None,
            routed_to="real_http",
            backend_port=28080,
            decision_stage="backend_observation",
            log_bucket="real_logs",
            decision_id=row.get("decision_id"),
            request_id=row.get("request_id"),
            session_id=row.get("session_id"),
        )
        add_event(events, seen, normalized_event)


def sort_key(event):
    return (
        event.get("timestamp_utc") or "",
        event.get("log_origin") or "",
        event.get("source_ip") or "",
        event.get("path") or "",
        event.get("event_type") or "",
        event.get("request_id") or "",
        event.get("decision_id") or "",
    )


def parse_args():
    parser = argparse.ArgumentParser(description="Router-owned HTTP normalizer test")
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="Output JSONL path. Defaults to a test file inside /router.",
    )
    parser.add_argument(
        "--max-lines-per-file",
        type=int,
        default=0,
        help="Read only the first N valid JSON lines from each input file for smoke testing.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    events = []
    seen = set()

    limit = max(int(args.max_lines_per_file or 0), 0)

    load_routing_decisions(events, seen, limit=limit)
    load_ingress(events, seen, limit=limit)
    load_honeypot(events, seen, limit=limit)
    load_real_backend(events, seen, limit=limit)

    events.sort(key=sort_key)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as out:
        for event in events:
            out.write(json.dumps(event, ensure_ascii=False) + "\n")

    print(f"Wrote {len(events)} HTTP normalized events to {output_path}")


if __name__ == "__main__":
    main()
