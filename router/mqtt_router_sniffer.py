import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


ROUTER_DIR = Path(__file__).resolve().parent
if str(ROUTER_DIR) not in sys.path:
    sys.path.insert(0, str(ROUTER_DIR))


from mqtt_wire import MQTTProtocolError, iter_publish_messages, open_client, subscribe
from session_router import SessionRouter


BROKER_HOST = os.environ.get("MQTT_BROKER_HOST", "127.0.0.1")
BROKER_PORT = int(os.environ.get("MQTT_BROKER_PORT", "1883"))
BROKER_KEEPALIVE = int(os.environ.get("MQTT_BROKER_KEEPALIVE", "60"))
CLIENT_ID = os.environ.get("MQTT_SNIFFER_CLIENT_ID", "mqtt-router-sniffer-host")
TOPIC_FILTER = os.environ.get("MQTT_TOPIC_FILTER", "#")

LOG_DIR = Path("/opt/iot-honeypot/logs")
COMBINED_LOG = LOG_DIR / "mqtt_router_messages.jsonl"
REAL_LOG = LOG_DIR / "mqtt_real.jsonl"
HONEYPOT_LOG = LOG_DIR / "mqtt_honeypot.jsonl"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def append_jsonl(path, record):
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def parse_payload_text(payload_bytes):
    try:
        return payload_bytes.decode("utf-8", errors="replace")
    except Exception:
        return repr(payload_bytes)


def parse_payload_object(payload_text):
    try:
        value = json.loads(payload_text)
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def derive_source_ip(topic, payload_object):
    for key in ("source_ip", "src_ip", "ip"):
        value = str(payload_object.get(key) or "").strip()
        if value:
            return value
    return f"mqtt_topic::{topic}"


def build_router_event(topic, payload_text, payload_object):
    event_type = str(payload_object.get("event") or payload_object.get("action") or "message").lower()
    source_ip = derive_source_ip(topic, payload_object)
    return {
        "timestamp_utc": utc_now(),
        "source_ip": source_ip,
        "protocol": "mqtt",
        "event_type": event_type,
        "destination_port": BROKER_PORT,
        "topic": topic,
        "payload": payload_text[:2000],
        "test_id": payload_object.get("test_id"),
    }


def build_log_record(topic, payload_text, payload_object, packet, decision):
    source_ip = derive_source_ip(topic, payload_object)
    return {
        "ts": utc_now(),
        "service": "mqtt",
        "event": str(payload_object.get("event") or payload_object.get("action") or "message").lower(),
        "topic": topic,
        "qos": packet["qos"],
        "retain": packet["retain"],
        "payload": payload_text[:2000],
        "source_ip": source_ip,
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


def run_forever():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    router = SessionRouter()

    while True:
        sock = None
        try:
            sock = open_client(
                host=BROKER_HOST,
                port=BROKER_PORT,
                client_id=CLIENT_ID,
                keepalive=BROKER_KEEPALIVE,
            )
            subscribe(sock, topic_filter=TOPIC_FILTER, qos=0)
            print(
                f"[{utc_now()}] MQTT router sniffer subscribed to {BROKER_HOST}:{BROKER_PORT} topic={TOPIC_FILTER}",
                flush=True,
            )

            for packet in iter_publish_messages(sock, keepalive=BROKER_KEEPALIVE):
                topic = packet["topic"]
                payload_text = parse_payload_text(packet["payload_bytes"])
                payload_object = parse_payload_object(payload_text)
                router_event = build_router_event(topic, payload_text, payload_object)
                decision = router.decide(dict(router_event))
                record = build_log_record(topic, payload_text, payload_object, packet, decision)

                append_jsonl(COMBINED_LOG, record)
                if record["route_decision"] == "honeypot":
                    append_jsonl(HONEYPOT_LOG, record)
                else:
                    append_jsonl(REAL_LOG, record)

        except (ConnectionError, OSError, MQTTProtocolError) as exc:
            print(f"[{utc_now()}] MQTT router sniffer reconnecting after error: {exc}", flush=True)
            time.sleep(2)
        except Exception as exc:
            print(f"[{utc_now()}] MQTT router sniffer unexpected error: {exc}", flush=True)
            time.sleep(2)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass


if __name__ == "__main__":
    run_forever()
