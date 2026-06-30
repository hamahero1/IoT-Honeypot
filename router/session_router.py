# /opt/iot-honeypot/router/session_router.py
# ============================================================
# Main routing engine for the Lightsail ingress flow
# Internet -> Router -> First Decision -> Real/Honeypot -> Logs -> ML
# ============================================================

import json
import os
import sys
from datetime import datetime, timezone
from uuid import uuid4

from state_cache import DEFAULT_SESSION_TTL_SECONDS, StateCache
from rules import HTTP_HONEYPOT_BACKEND_PORT, HTTP_REAL_BACKEND_PORT, build_routing_context, evaluate_rules


ROUTING_LOG_PATH = "/opt/iot-honeypot/logs/routing_decisions.jsonl"


ROUTE_TARGETS = {
    "http": {
        "real": {
            "routed_to": "real_http",
            "backend_port": HTTP_REAL_BACKEND_PORT,
            "log_bucket": "real_logs",
        },
        "honeypot": {
            "routed_to": "http_honeypot",
            "backend_port": HTTP_HONEYPOT_BACKEND_PORT,
            "log_bucket": "honeypot_logs",
        },
    },
    "ssh": {
        "real": {
            "routed_to": "real_ssh",
            "backend_port": None,
            "log_bucket": "real_logs",
        },
        "honeypot": {
            "routed_to": "ssh_honeypot",
            "backend_port": None,
            "log_bucket": "honeypot_logs",
        },
    },
    "mqtt": {
        "real": {
            "routed_to": "real_mqtt",
            "backend_port": None,
            "log_bucket": "real_logs",
        },
        "honeypot": {
            "routed_to": "mqtt_honeypot",
            "backend_port": None,
            "log_bucket": "honeypot_logs",
        },
    },
    "rtsp": {
        "real": {
            "routed_to": "real_rtsp",
            "backend_port": None,
            "log_bucket": "real_logs",
        },
        "honeypot": {
            "routed_to": "rtsp_honeypot",
            "backend_port": None,
            "log_bucket": "honeypot_logs",
        },
    },
    "default": {
        "real": {
            "routed_to": "real_service",
            "backend_port": None,
            "log_bucket": "real_logs",
        },
        "honeypot": {
            "routed_to": "generic_honeypot",
            "backend_port": None,
            "log_bucket": "honeypot_logs",
        },
    },
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


class SessionRouter:
    def __init__(
        self,
        cache_path="/opt/iot-honeypot/router/state_cache.json",
        session_ttl_seconds=DEFAULT_SESSION_TTL_SECONDS,
    ):
        self.cache = StateCache(cache_path, session_ttl_seconds=session_ttl_seconds)

    def decide(self, event):
        routing_context = build_routing_context(event)
        source_ip = str(event.get("source_ip") or event.get("src_ip") or event.get("ip") or "unknown")
        protocol = routing_context["protocol"]
        event_type = str(event.get("event_type", routing_context["event_type"]) or "unknown").lower()
        ingress_port = routing_context["ingress_port"]
        request_id = str(event.get("request_id") or event.get("req_id") or "")
        session_id = str(event.get("session_id") or event.get("sess_id") or "")
        decision_id = str(event.get("decision_id") or f"rd-{uuid4()}")

        ip_state = self.cache.get_ip_state(source_ip)
        session_state = self.cache.get_session_state(session_id) if protocol == "http" else {}
        route, reasons, score = evaluate_rules(event, ip_state, session_state=session_state)

        target = self._resolve_target(protocol, route)

        event["route_decision"] = route
        event["route_label"] = 1 if route == "honeypot" else 0
        event["protocol"] = protocol
        event["ingress_port"] = ingress_port
        event["decision_stage"] = "first_decision"
        event["routed_to"] = target["routed_to"]
        event["backend_port"] = target["backend_port"]
        event["log_bucket"] = target["log_bucket"]
        event["next_stage"] = "ml_engine"
        event["decision_id"] = decision_id

        # HTTP stickiness is session-based. Other protocols still use IP-based state.
        if protocol == "http":
            self._update_http_session_state(
                session_id=session_id,
                source_ip=source_ip,
                route=route,
                reasons=reasons,
                score=score,
                protocol=protocol,
            )
        elif route == "honeypot":
            self.cache.mark_suspicious(
                source_ip=source_ip,
                reason=";".join(reasons),
                protocol=protocol
            )

            current_state = self.cache.get_ip_state(source_ip)
            suspicious_count = int(current_state.get("suspicious_count", 0))

            # SSH is a pure honeypot path (no legitimate users connect over it),
            # so the first suspicious packet locks the whole source to the
            # honeypot for the session-timeout window. Subsequent SSH packets
            # then resolve to honeypot via the IP `flagged` check in rules.py
            # instead of being re-judged per-packet and flipping back to "real".
            # Other protocols still require escalation before the IP is flagged.
            if protocol == "ssh" or score >= 5 or suspicious_count >= 3:
                self.cache.mark_flagged(
                    source_ip=source_ip,
                    reason=";".join(reasons),
                    protocol=protocol,
                    attack_type=protocol
                )

        self.cache.mark_route(
            source_ip=source_ip,
            route=route,
            reason=";".join(reasons),
            protocol=protocol
        )

        decision = {
            "decision_id": decision_id,
            "timestamp_utc": utc_now(),
            "source_ip": source_ip,
            "protocol": protocol,
            "ingress_port": ingress_port,
            "event_type": event_type,
            "destination_port": event.get("destination_port", event.get("dst_port", ingress_port)),
            "decision_stage": event["decision_stage"],
            "route_decision": event["route_decision"],
            "route_label": event["route_label"],
            "routed_to": event["routed_to"],
            "backend_port": event["backend_port"],
            "log_bucket": event["log_bucket"],
            "next_stage": event["next_stage"],
            "score": score,
            "reason": reasons,
            "request_id": request_id or None,
            "session_id": session_id or None,
            "path": event.get("path") or event.get("request_path"),
            "topic": event.get("topic"),
            "close_reason": event.get("close_reason"),
            "client_id": event.get("client_id"),
            "connection_id": event.get("connection_id"),
            "test_id": event.get("test_id"),
        }

        self._write_decision_log(decision)
        return decision

    def _write_decision_log(self, decision):
        os.makedirs(os.path.dirname(ROUTING_LOG_PATH), exist_ok=True)
        with open(ROUTING_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(decision) + "\n")

    def _resolve_target(self, protocol, route):
        target_group = ROUTE_TARGETS.get(protocol, ROUTE_TARGETS["default"])
        return target_group.get(route, ROUTE_TARGETS["default"][route])

    def _update_http_session_state(self, session_id, source_ip, route, reasons, score, protocol):
        reason_text = ";".join(reasons)

        if route == "honeypot":
            # Hold the source IP for the same 30-minute window as the HTTP
            # session so clients that drop cookies cannot escape the honeypot.
            self.cache.mark_http_source_timeout(
                source_ip=source_ip,
                reason=reason_text,
            )

        if not session_id:
            return

        if route == "honeypot":
            self.cache.mark_session_suspicious(
                session_id=session_id,
                source_ip=source_ip,
                reason=reason_text,
                protocol=protocol,
            )

            self.cache.mark_session_flagged(
                session_id=session_id,
                source_ip=source_ip,
                reason=reason_text,
                protocol=protocol,
                attack_type=protocol,
            )

        self.cache.mark_session_route(
            session_id=session_id,
            source_ip=source_ip,
            route=route,
            reason=reason_text,
            protocol=protocol,
        )


def load_event():
    """
    Smart input handler:
    - If input is piped -> read from stdin
    - If run directly -> use sample event
    """
    if not sys.stdin.isatty():
        try:
            raw = sys.stdin.read().strip()
            if raw:
                return json.loads(raw)
        except Exception:
            pass

    return {
        "source_ip": "185.220.101.45",
        "protocol": "http",
        "event_type": "request",
        "destination_port": 80,
        "path": "/admin",
        "payload": "GET /admin HTTP/1.1"
    }


if __name__ == "__main__":
    router = SessionRouter()
    event = load_event()
    result = router.decide(event)
    print(json.dumps(result, indent=2))
