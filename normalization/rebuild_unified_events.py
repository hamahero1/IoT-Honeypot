import json
import os
import subprocess
import re
from collections import deque
from pathlib import Path

BASE = Path("/opt/iot-honeypot")
OUTPUT = BASE / "normalized" / "unified_events.jsonl"
MAX_LINES_PER_SOURCE = int(os.environ.get("REBUILD_MAX_LINES_PER_SOURCE", "0") or "0")
MAX_SSH_FILES = int(os.environ.get("REBUILD_MAX_SSH_FILES", "7") or "7")
PROTOCOL_FILTER = {
    value.strip().lower()
    for value in os.environ.get("REBUILD_PROTOCOL_FILTER", "").split(",")
    if value.strip()
}
HTTP_HONEYPOT_INPUT = BASE / "logs" / "http_honeypot.jsonl"
HTTP_INGRESS_INPUT = BASE / "logs" / "http_ingress_80.jsonl"
HTTP_ROUTING_INPUT = BASE / "logs" / "routing_decisions.jsonl"
HTTP_REAL_INPUT = BASE / "logs" / "http_real_28080.jsonl"
MQTT_ROUTER_INPUT = BASE / "logs" / "mqtt_router_messages.jsonl"
MQTT_INPUT = BASE / "logs" / "mqtt_messages.jsonl"
RTSP_ROUTER_INPUT = BASE / "logs" / "rtsp_router_events.jsonl"
RTSP_FILE = BASE / "rtsp" / "logs" / "mediamtx.log"
COWRIE_DIR = BASE / "logs" / "cowrie"

EVENT_MAP = {
    "cowrie.session.connect": "connection_opened",
    "cowrie.session.closed": "connection_closed",
    "cowrie.login.failed": "login_attempt",
    "cowrie.login.success": "login_success",
    "cowrie.command.input": "command_executed",
    "cowrie.session.file_download": "file_download",
    "cowrie.session.file_upload": "file_upload",
    "cowrie.client.kex": "client_fingerprint"
}

def add_event(events, seen, event):
    line = json.dumps(event, ensure_ascii=False, sort_keys=True)
    if line not in seen:
        seen.add(line)
        events.append(event)

def iter_text_lines(path):
    if MAX_LINES_PER_SOURCE > 0:
        try:
            result = subprocess.run(
                ["tail", "-n", str(MAX_LINES_PER_SOURCE), str(path)],
                capture_output=True,
                check=False,
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
            for line in result.stdout.splitlines(keepends=True):
                yield line
            return
        except Exception:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                for line in deque(f, maxlen=MAX_LINES_PER_SOURCE):
                    yield line
            return

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            yield line

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

def build_base_event(timestamp_utc, source_ip, protocol, event_type, payload, response_status):
    return {
        "timestamp_utc": timestamp_utc,
        "source_ip": first_source_ip(source_ip),
        "protocol": protocol,
        "event_type": event_type,
        "username": None,
        "password": None,
        "command": None,
        "payload": payload,
        "response_status": response_status,
    }

def attach_router_fields(
    event,
    *,
    log_origin,
    path=None,
    topic=None,
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
    client_id=None,
    connection_id=None,
    test_id=None,
):
    # Router integration: preserve the old normalized shape and carry router
    # decision metadata into unified events for later feature extraction and ML.
    event["log_origin"] = log_origin
    event["path"] = path
    event["topic"] = topic
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
    event["client_id"] = client_id
    event["connection_id"] = connection_id
    event["test_id"] = test_id
    return event

def load_ssh(events, seen):
    if not COWRIE_DIR.exists():
        return

    ssh_paths = [
        path for path in sorted(COWRIE_DIR.glob("cowrie.json*"))
        if not path.name.endswith(".log")
    ]

    if MAX_LINES_PER_SOURCE > 0 and MAX_SSH_FILES > 0:
        current_paths = [path for path in ssh_paths if path.name == "cowrie.json"]
        rotated_paths = [path for path in ssh_paths if path.name != "cowrie.json"]
        ssh_paths = rotated_paths[-max(MAX_SSH_FILES - len(current_paths), 0):] + current_paths

    for path in ssh_paths:

        for line in iter_text_lines(path):
                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                eventid = event.get("eventid", "unknown")

                command_value = (
                    event.get("input")
                    or event.get("command")
                    or event.get("cmd")
                )

                normalized_event = {
                    "timestamp_utc": event.get("timestamp"),
                    "source_ip": event.get("src_ip"),
                    "protocol": "ssh",
                    "event_type": EVENT_MAP.get(eventid, eventid),
                    "username": event.get("username"),
                    "password": event.get("password"),
                    "command": command_value,
                    "payload": event.get("message"),
                    "response_status": None
                }

                add_event(events, seen, normalized_event)

def load_http_honeypot(events, seen):
    if not HTTP_HONEYPOT_INPUT.exists():
        return

    for line in iter_text_lines(HTTP_HONEYPOT_INPUT):
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            body = event.get("body")
            extra = event.get("extra") or {}
            headers = event.get("headers") or {}
            username = event.get("username") or extra.get("username")
            password = event.get("password") or extra.get("password")

            normalized_event = build_base_event(
                event.get("timestamp_utc"),
                event.get("ip"),
                "http",
                "login_attempt" if (username or password) else "http_request",
                body,
                event.get("response_status")
            )
            normalized_event["username"] = username
            normalized_event["password"] = password
            attach_router_fields(
                normalized_event,
                log_origin="http_honeypot",
                path=event.get("path"),
                method=event.get("method"),
                query_string=event.get("query_string"),
                user_agent=event.get("user_agent"),
                route_decision=headers.get("X-Route-Decision") or "honeypot",
                route_label=1,
                score=None,
                reason=None,
                routed_to=headers.get("X-Routed-To") or "http_honeypot",
                backend_port=8080,
                decision_stage="backend_observation",
                log_bucket="honeypot_logs",
                decision_id=headers.get("X-Decision-Id"),
                request_id=headers.get("X-Request-Id"),
                session_id=headers.get("X-Session-Id"),
                client_id=None,
                connection_id=None,
                test_id=None,
            )

            add_event(events, seen, normalized_event)

def load_http_ingress(events, seen):
    if not HTTP_INGRESS_INPUT.exists():
        return

    for line in iter_text_lines(HTTP_INGRESS_INPUT):
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            route_decision = event.get("route_decision")
            normalized_event = build_base_event(
                event.get("timestamp_utc"),
                event.get("source_ip"),
                "http",
                event.get("event_type", "ingress_request"),
                event.get("payload"),
                event.get("response_status")
            )
            attach_router_fields(
                normalized_event,
                log_origin="http_ingress_80",
                path=event.get("path"),
                method=event.get("method"),
                query_string=event.get("query_string"),
                user_agent=event.get("user_agent"),
                route_decision=route_decision,
                route_label=route_label_from_decision(route_decision),
                score=event.get("decision_score"),
                reason=event.get("decision_reason"),
                routed_to=event.get("routed_to"),
                backend_port=event.get("backend_port"),
                decision_stage="first_decision",
                log_bucket=event.get("log_bucket"),
                decision_id=event.get("decision_id"),
                request_id=event.get("request_id"),
                session_id=event.get("session_id"),
                client_id=None,
                connection_id=None,
                test_id=event.get("test_id"),
            )

            add_event(events, seen, normalized_event)

def load_routing_decisions(events, seen):
    if not HTTP_ROUTING_INPUT.exists():
        return

    for line in iter_text_lines(HTTP_ROUTING_INPUT):
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            protocol = str(event.get("protocol") or "").lower() or "unknown"
            if not protocol_enabled(protocol):
                continue

            route_decision = event.get("route_decision")
            normalized_event = build_base_event(
                event.get("timestamp_utc"),
                event.get("source_ip"),
                protocol,
                "router_decision",
                event.get("path") or event.get("topic"),
                None
            )
            attach_router_fields(
                normalized_event,
                log_origin="routing_decisions",
                path=event.get("path"),
                topic=event.get("topic"),
                route_decision=route_decision,
                route_label=event.get("route_label", route_label_from_decision(route_decision)),
                score=event.get("score"),
                reason=event.get("reason"),
                routed_to=event.get("routed_to"),
                backend_port=event.get("backend_port"),
                decision_stage=event.get("decision_stage"),
                log_bucket=event.get("log_bucket"),
                decision_id=event.get("decision_id"),
                request_id=event.get("request_id"),
                session_id=event.get("session_id"),
                client_id=event.get("client_id"),
                connection_id=event.get("connection_id"),
                test_id=event.get("test_id"),
            )

            add_event(events, seen, normalized_event)

def load_http_real(events, seen):
    if not HTTP_REAL_INPUT.exists():
        return

    for line in iter_text_lines(HTTP_REAL_INPUT):
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            normalized_event = build_base_event(
                event.get("timestamp_utc"),
                event.get("source_ip"),
                "http",
                "http_request",
                event.get("path"),
                event.get("status_code")
            )
            attach_router_fields(
                normalized_event,
                log_origin="http_real_28080",
                path=event.get("path"),
                method=event.get("method"),
                user_agent=event.get("user_agent"),
                route_decision="real",
                route_label=0,
                score=None,
                reason=None,
                routed_to="real_http",
                backend_port=28080,
                decision_stage="backend_observation",
                log_bucket="real_logs",
                decision_id=event.get("decision_id"),
                request_id=event.get("request_id"),
                session_id=event.get("session_id"),
                client_id=None,
                connection_id=None,
                test_id=None,
            )

            add_event(events, seen, normalized_event)

def load_mqtt(events, seen):
    mqtt_inputs = []
    if MQTT_ROUTER_INPUT.exists():
        mqtt_inputs.append((MQTT_ROUTER_INPUT, "mqtt_router_messages"))
    elif MQTT_INPUT.exists():
        mqtt_inputs.append((MQTT_INPUT, "mqtt_messages"))

    for input_path, log_origin in mqtt_inputs:
        for line in iter_text_lines(input_path):
                line = line.strip()
                if not line:
                    continue

                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                topic = data.get("topic", "unknown_topic")
                payload = data.get("payload")
                event_name = data.get("event", "message")
                route_decision = data.get("route_decision")
                source_ip = data.get("source_ip") or data.get("ip") or f"mqtt_topic::{topic}"

                normalized_event = {
                    "timestamp_utc": data.get("ts"),
                    "source_ip": source_ip,
                    "protocol": "mqtt",
                    "event_type": event_name,
                    "username": None,
                    "password": None,
                    "command": None,
                    "payload": json.dumps({
                        "topic": topic,
                        "payload": payload,
                        "qos": data.get("qos"),
                        "retain": data.get("retain"),
                        "test_id": data.get("test_id"),
                    }, ensure_ascii=False),
                    "response_status": None
                }
                attach_router_fields(
                    normalized_event,
                    log_origin=log_origin,
                    topic=topic,
                    route_decision=route_decision,
                    route_label=data.get("route_label", route_label_from_decision(route_decision)),
                    score=data.get("score"),
                    reason=data.get("reason"),
                    routed_to=data.get("routed_to"),
                    backend_port=data.get("backend_port"),
                    decision_stage=data.get("decision_stage"),
                    log_bucket=data.get("log_bucket"),
                    decision_id=data.get("decision_id"),
                    request_id=None,
                    session_id=None,
                    client_id=data.get("client_id"),
                    connection_id=data.get("connection_id"),
                    test_id=data.get("test_id"),
                )

                add_event(events, seen, normalized_event)

def load_rtsp_router(events, seen):
    if not RTSP_ROUTER_INPUT.exists():
        return False

    loaded = False
    for line in iter_text_lines(RTSP_ROUTER_INPUT):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            route_decision = data.get("route_decision")
            normalized_event = build_base_event(
                data.get("timestamp_utc"),
                data.get("source_ip"),
                "rtsp",
                data.get("event_type", "connection"),
                data.get("payload"),
                None
            )
            attach_router_fields(
                normalized_event,
                log_origin="rtsp_router_events",
                path=data.get("path"),
                topic=None,
                route_decision=route_decision,
                route_label=data.get("route_label", route_label_from_decision(route_decision)),
                score=data.get("score"),
                reason=data.get("reason"),
                routed_to=data.get("routed_to"),
                backend_port=data.get("backend_port"),
                decision_stage=data.get("decision_stage"),
                log_bucket=data.get("log_bucket"),
                decision_id=data.get("decision_id"),
                request_id=None,
                session_id=None,
                client_id=None,
                connection_id=data.get("connection_id"),
                test_id=data.get("test_id"),
            )
            normalized_event["close_reason"] = data.get("close_reason")
            normalized_event["source_port"] = data.get("source_port")

            add_event(events, seen, normalized_event)
            loaded = True

    return loaded

def parse_rtsp_lines(lines, events, seen):
    for line in lines:
        if "[conn" not in line and "[session" not in line:
            continue

        ts = re.search(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})', line)
        ip = re.search(r'(\d+\.\d+\.\d+\.\d+):\d+', line)

        if not ip:
            continue

        if " opened" in line:
            event_type = "connection_opened"
        elif " closed:" in line:
            event_type = "connection_closed"
        elif "is reading from path" in line:
            event_type = "stream_read"
        elif "created by" in line:
            event_type = "session_created"
        elif "destroyed:" in line:
            event_type = "session_destroyed"
        else:
            event_type = "connection"

        normalized_event = {
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

        add_event(events, seen, normalized_event)

def load_rtsp(events, seen):
    if RTSP_FILE.exists():
        parse_rtsp_lines(list(iter_text_lines(RTSP_FILE)), events, seen)
        return

    try:
        tail_arg = f"--tail {MAX_LINES_PER_SOURCE}" if MAX_LINES_PER_SOURCE > 0 else ""
        logs = subprocess.check_output(f"docker logs {tail_arg} rtsp-camera 2>/dev/null", shell=True, text=True)
        parse_rtsp_lines(logs.splitlines(), events, seen)
    except Exception:
        pass

def sort_key(e):
    return (
        e.get("timestamp_utc") or "",
        e.get("protocol") or "",
        e.get("source_ip") or "",
        e.get("event_type") or "",
        e.get("command") or "",
        e.get("payload") or ""
    )

def protocol_enabled(protocol_name):
    if not PROTOCOL_FILTER:
        return True
    return protocol_name in PROTOCOL_FILTER

def main():
    events = []
    seen = set()

    if protocol_enabled("ssh"):
        load_ssh(events, seen)
    if protocol_enabled("http"):
        load_http_honeypot(events, seen)
        load_http_ingress(events, seen)
        load_http_real(events, seen)
    if protocol_enabled("mqtt"):
        load_mqtt(events, seen)
    if protocol_enabled("rtsp"):
        if not load_rtsp_router(events, seen):
            load_rtsp(events, seen)
    load_routing_decisions(events, seen)

    events.sort(key=sort_key)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", encoding="utf-8") as out:
        for event in events:
            out.write(json.dumps(event, ensure_ascii=False) + "\n")

    print(f"Wrote {len(events)} events to {OUTPUT}")

if __name__ == "__main__":
    main()
