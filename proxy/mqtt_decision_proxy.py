#!/usr/bin/env python3
import argparse
import json
import socket
import socketserver
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

_LOG_LOCK = threading.Lock()


ROUTER_DIR = Path(__file__).resolve().parents[1]
if str(ROUTER_DIR) not in sys.path:
    sys.path.insert(0, str(ROUTER_DIR))


from mqtt_wire import MQTTProtocolError, read_exact, read_remaining_length
from session_router import SessionRouter


LOG_DIR = Path("/opt/iot-honeypot/logs")
INGRESS_LOG = LOG_DIR / "mqtt_ingress_1883.jsonl"
COMBINED_LOG = LOG_DIR / "mqtt_router_messages.jsonl"
REAL_LOG = LOG_DIR / "mqtt_real.jsonl"
HONEYPOT_LOG = LOG_DIR / "mqtt_honeypot.jsonl"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def append_jsonl(path, record):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, ensure_ascii=False) + "\n"
    with _LOG_LOCK:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line)


def encode_varint(value):
    encoded = bytearray()
    value = int(value)
    while True:
        digit = value % 128
        value //= 128
        if value > 0:
            digit |= 0x80
        encoded.append(digit)
        if value == 0:
            break
    return bytes(encoded)


def read_packet(sock):
    first = sock.recv(1)
    if not first:
        return None

    remaining_bytes = bytearray()
    multiplier = 1
    remaining_length = 0

    while True:
        digit_raw = read_exact(sock, 1)
        digit = digit_raw[0]
        remaining_bytes.extend(digit_raw)
        remaining_length += (digit & 0x7F) * multiplier
        if (digit & 0x80) == 0:
            break
        multiplier *= 128
        if multiplier > 128 * 128 * 128:
            raise MQTTProtocolError("invalid remaining length")

    payload = read_exact(sock, remaining_length) if remaining_length else b""
    return {
        "first_byte": first[0],
        "payload": payload,
        "raw": first + bytes(remaining_bytes) + payload,
    }


def read_utf8(payload, offset):
    if len(payload) < offset + 2:
        return "", offset
    length = int.from_bytes(payload[offset:offset + 2], "big")
    offset += 2
    value = payload[offset:offset + length].decode("utf-8", errors="replace")
    return value, offset + length


def parse_connect(payload):
    protocol_name, offset = read_utf8(payload, 0)
    if len(payload) < offset + 4:
        return {"protocol_name": protocol_name}

    protocol_level = payload[offset]
    connect_flags = payload[offset + 1]
    keepalive = int.from_bytes(payload[offset + 2:offset + 4], "big")
    offset += 4
    client_id, offset = read_utf8(payload, offset)

    # Extract optional will topic/message (must be skipped to reach credentials)
    if connect_flags & 0x04:  # Will Flag
        _, offset = read_utf8(payload, offset)  # will topic
        _, offset = read_utf8(payload, offset)  # will message

    username = None
    password = None
    if connect_flags & 0x80:  # User Name Flag
        username, offset = read_utf8(payload, offset)
    if connect_flags & 0x40:  # Password Flag
        password, offset = read_utf8(payload, offset)

    return {
        "protocol_name": protocol_name,
        "protocol_level": protocol_level,
        "connect_flags": connect_flags,
        "keepalive": keepalive,
        "client_id": client_id,
        "username": username,
        "password": password,
    }


def parse_subscribe(payload):
    if len(payload) < 2:
        return {"packet_id": None, "topics": []}

    packet_id = int.from_bytes(payload[:2], "big")
    offset = 2
    topics = []
    while offset < len(payload):
        topic_filter, offset = read_utf8(payload, offset)
        qos = payload[offset] if offset < len(payload) else 0
        offset += 1
        topics.append({"topic": topic_filter, "qos": qos})

    return {"packet_id": packet_id, "topics": topics}


def parse_publish(first_byte, payload):
    qos = (first_byte >> 1) & 0x03
    retain = bool(first_byte & 0x01)
    dup = bool(first_byte & 0x08)
    topic, offset = read_utf8(payload, 0)
    packet_id = None

    if qos > 0 and len(payload) >= offset + 2:
        packet_id = int.from_bytes(payload[offset:offset + 2], "big")
        offset += 2

    payload_bytes = payload[offset:]
    payload_text = payload_bytes.decode("utf-8", errors="replace")

    return {
        "topic": topic,
        "payload": payload_text,
        "payload_size": len(payload_bytes),
        "qos": qos,
        "retain": retain,
        "dup": dup,
        "packet_id": packet_id,
    }


def parse_payload_object(payload_text):
    try:
        value = json.loads(payload_text)
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def build_puback(packet_id):
    return b"\x40\x02" + int(packet_id).to_bytes(2, "big")


class MQTTProxyHandler(socketserver.BaseRequestHandler):
    router = None
    upstream_host = "127.0.0.1"
    upstream_port = 11883
    ingress_port_label = 1883

    def setup(self):
        self.client_ip, self.client_port = self.client_address[:2]
        self.client_id = None
        self.connection_id = f"mqtt-{uuid4()}"
        self.connect_username = None
        self.connect_password = None
        self.stop_event = threading.Event()

    def handle(self):
        try:
            upstream = socket.create_connection((self.upstream_host, self.upstream_port), timeout=5)
        except OSError as exc:
            self.log_error(exc)
            return
        upstream.settimeout(1.0)
        self.request.settimeout(1.0)

        broker_thread = threading.Thread(
            target=self.forward_broker_to_client,
            args=(upstream,),
            daemon=True,
        )
        broker_thread.start()

        try:
            self.forward_client_to_broker(upstream)
        finally:
            self.stop_event.set()
            try:
                upstream.close()
            except OSError:
                pass

    def forward_broker_to_client(self, upstream):
        while not self.stop_event.is_set():
            try:
                packet = read_packet(upstream)
                if packet is None:
                    break
                self.request.sendall(packet["raw"])
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception:
                break

        self.stop_event.set()

    def forward_client_to_broker(self, upstream):
        while not self.stop_event.is_set():
            try:
                packet = read_packet(self.request)
                if packet is None:
                    break

                packet_type = packet["first_byte"] >> 4
                should_forward = True

                if packet_type == 1:
                    details = parse_connect(packet["payload"])
                    self.client_id = details.get("client_id") or self.connection_id
                    self.connect_username = details.get("username")
                    self.connect_password = details.get("password")
                    self.log_connection(details)

                elif packet_type == 3:
                    details = parse_publish(packet["first_byte"], packet["payload"])
                    decision = self.decide_and_log("message", details)
                    should_forward = decision.get("route_decision") == "real"
                    if not should_forward and details.get("qos") == 1 and details.get("packet_id") is not None:
                        self.request.sendall(build_puback(details["packet_id"]))

                elif packet_type == 8:
                    details = parse_subscribe(packet["payload"])
                    for topic in details.get("topics", []):
                        self.decide_and_log("subscribe", {
                            "topic": topic.get("topic"),
                            "payload": "",
                            "qos": topic.get("qos", 0),
                            "retain": False,
                            "packet_id": details.get("packet_id"),
                        })

                if should_forward:
                    upstream.sendall(packet["raw"])

            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as exc:
                self.log_error(exc)
                break

        self.stop_event.set()

    def build_router_event(self, event_type, details):
        payload_object = parse_payload_object(str(details.get("payload") or ""))
        return {
            "timestamp_utc": utc_now(),
            "source_ip": self.client_ip,
            "protocol": "mqtt",
            "event_type": event_type,
            "destination_port": self.ingress_port_label,
            "topic": details.get("topic"),
            "payload": str(details.get("payload") or "")[:2000],
            "client_id": self.client_id,
            "connection_id": self.connection_id,
            "username": self.connect_username,
            "password": self.connect_password,
            "test_id": payload_object.get("test_id"),
        }

    def decide_and_log(self, event_type, details):
        router_event = self.build_router_event(event_type, details)
        decision = self.router.decide(dict(router_event))
        payload_object = parse_payload_object(str(details.get("payload") or ""))

        record = {
            "ts": utc_now(),
            "service": "mqtt",
            "event": event_type,
            "source_ip": self.client_ip,
            "source_port": self.client_port,
            "client_id": self.client_id,
            "connection_id": self.connection_id,
            "topic": details.get("topic"),
            "qos": details.get("qos"),
            "retain": bool(details.get("retain", False)),
            "payload": str(details.get("payload") or "")[:2000],
            "payload_size": details.get("payload_size"),
            "test_id": payload_object.get("test_id"),
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

        append_jsonl(INGRESS_LOG, record)
        append_jsonl(COMBINED_LOG, record)
        if record["route_decision"] == "honeypot":
            append_jsonl(HONEYPOT_LOG, record)
        else:
            append_jsonl(REAL_LOG, record)

        return decision

    def log_connection(self, details):
        record = {
            "ts": utc_now(),
            "service": "mqtt",
            "event": "connect",
            "source_ip": self.client_ip,
            "source_port": self.client_port,
            "client_id": self.client_id,
            "connection_id": self.connection_id,
            "protocol_name": details.get("protocol_name"),
            "protocol_level": details.get("protocol_level"),
            "keepalive": details.get("keepalive"),
        }
        append_jsonl(INGRESS_LOG, record)

    def log_error(self, exc):
        record = {
            "ts": utc_now(),
            "service": "mqtt",
            "event": "proxy_error",
            "source_ip": self.client_ip,
            "source_port": self.client_port,
            "client_id": self.client_id,
            "connection_id": self.connection_id,
            "error": str(exc),
        }
        append_jsonl(INGRESS_LOG, record)


class ThreadingMQTTProxy(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser(description="MQTT router decision proxy")
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=1883)
    parser.add_argument("--broker-host", default="127.0.0.1")
    parser.add_argument("--broker-port", type=int, default=11883)
    parser.add_argument("--ingress-port-label", type=int, default=1883)
    parser.add_argument("--cache-path", default="/opt/iot-honeypot/router/state_cache.json")
    args = parser.parse_args()

    MQTTProxyHandler.router = SessionRouter(cache_path=args.cache_path)
    MQTTProxyHandler.upstream_host = args.broker_host
    MQTTProxyHandler.upstream_port = args.broker_port
    MQTTProxyHandler.ingress_port_label = args.ingress_port_label

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with ThreadingMQTTProxy((args.listen_host, args.listen_port), MQTTProxyHandler) as server:
        print(
            f"MQTT decision proxy listening on {args.listen_host}:{args.listen_port} "
            f"-> {args.broker_host}:{args.broker_port}",
            flush=True,
        )
        server.serve_forever()


if __name__ == "__main__":
    main()
