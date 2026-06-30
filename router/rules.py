# /opt/iot-honeypot/router/rules.py

# ============================================================
# Lightsail ingress rules engine
# Compatible with session_router.py that expects:
#   route, reasons, score = evaluate_rules(event, ip_state, session_state=None)
# ============================================================

from urllib.parse import unquote


# -----------------------------
# Ingress / target config
# -----------------------------
PUBLIC_INGRESS_PORTS = {
    "http": 80,
    "ssh": 22,
    "mqtt": 1883,
    "rtsp": 554,
}

# Keep backend ports here for compatibility with older events
# that may already contain the internal destination port.
PROTOCOL_PORTS = {
    "http": {80, 8080, 28080},
    "ssh": {22},
    "mqtt": {1883},
    "rtsp": {554, 8554},
}

HTTP_REAL_BACKEND_PORT = 28080
HTTP_HONEYPOT_BACKEND_PORT = 8080
HTTP_BACKEND_PORTS = {HTTP_REAL_BACKEND_PORT, HTTP_HONEYPOT_BACKEND_PORT}


# -----------------------------
# HTTP config
# -----------------------------
SAFE_PATH_EXACT = {
    "/",
    "/index.html",
    "/home",
    "/about",
    "/favicon.ico",
    "/robots.txt",
    "/sitemap.xml",
}

SAFE_PATH_PREFIX = (
    "/static/",
    "/assets/",
    "/images/",
    "/css/",
    "/js/",
    "/products",
    "/api/cart",
    "/api/auth/login",
    "/api/v1/profile",
)

SCANNER_PATHS = (
    "/admin",
    "/wp-admin",
    "/wp-login",
    "/phpmyadmin",
    "/.env",
    "/.git",
    "/config",
    "/manager",
    "/actuator",
    "/console",
    "/cgi-bin",
    "/shell",
    "/cmd",
    "/boaform",
    "/hnap1",
    "/etc/passwd",
    "/etc/shadow",
)

BAD_USER_AGENTS = (
    "sqlmap",
    "nikto",
    "hydra",
    "dirbuster",
    "gobuster",
    "nmap",
    "masscan",
    "curl/",
    "python-requests",
)

GOOD_BOTS = (
    "googlebot",
    "bingbot",
)

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}


# -----------------------------
# Cross-protocol config
# -----------------------------
EXPLOIT_STRINGS = (
    "../",
    "..\\",
    "/etc/passwd",
    "/etc/shadow",
    "<script>",
    "union select",
    "or 1=1",
    "drop table",
    "cmd=",
    "exec=",
    "eval(",
    "system(",
    "/bin/sh",
    "/bin/bash",
    "wget ",
    "curl ",
    "chmod +x",
    "base64_decode",
    "nc -e",
)

SSH_SUSPICIOUS_EVENT_TYPES = {
    "login_attempt",
    "auth_failed",
    "login_failed",
    "password_failed",
}

SSH_SUSPICIOUS_COMMANDS = (
    "wget ",
    "curl ",
    "chmod +x",
    "busybox",
    "tftp",
    "nc ",
    "dropbear",
    "/bin/sh",
    "/bin/bash",
)

MQTT_SUSPICIOUS_TOPIC_MARKERS = (
    "#",
    "+",
    "$sys",
    "admin",
    "cmd",
    "shell",
    "config",
    "backup",
    "debug",
)

MQTT_SAFE_TOPIC_PREFIXES = (
    "office/",
    "sensor/",
    "sensors/",
    "telemetry/",
    "devices/",
    "home/",
    "status/",
)

RTSP_SUSPICIOUS_PATH_MARKERS = (
    "admin",
    "streaming/channels",
    "onvif",
    "snapshot",
    "cgi-bin",
    ".env",
    "config",
    "shell",
    "cmd",
)

RTSP_SUSPICIOUS_CLOSE_REASONS = (
    "invalid http request",
    "path",
    "not configured",
    "unexpected interleaved frame",
    "bad request",
    "unauthorized",
)

RTSP_SAFE_PATH_PREFIXES = (
    "live",
    "stream",
    "camera",
    "cam",
)


# -----------------------------
# Helpers
# -----------------------------
def _safe_str(value):
    if value is None:
        return ""
    return str(value)


def _safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def _safe_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def _norm_text(value):
    return unquote(_safe_str(value)).strip().lower()


def _contains_any(text, needles):
    return any(n in text for n in needles)


def _starts_with_any(text, prefixes):
    return any(text.startswith(p) for p in prefixes)


def _is_safe_path(path):
    if path in SAFE_PATH_EXACT:
        return True
    if _starts_with_any(path, SAFE_PATH_PREFIX):
        return True
    return False


def _is_scanner_path(path):
    if path in SCANNER_PATHS:
        return True
    return _contains_any(path, SCANNER_PATHS)


def _infer_protocol(protocol, dst_port):
    if protocol in PROTOCOL_PORTS:
        return protocol

    for maybe_protocol, ports in PROTOCOL_PORTS.items():
        if dst_port in ports:
            return maybe_protocol

    return protocol or "unknown"


def _infer_ingress_port(protocol, dst_port):
    if protocol in PUBLIC_INGRESS_PORTS:
        return PUBLIC_INGRESS_PORTS[protocol]
    return dst_port


def build_routing_context(event):
    raw_protocol = _norm_text(event.get("protocol"))
    has_http_shape = bool(
        event.get("method")
        or event.get("path")
        or event.get("request_path")
        or event.get("query_string")
    )
    if not raw_protocol and has_http_shape:
        raw_protocol = "http"

    dst_port = _safe_int(
        event.get(
            "destination_port",
            event.get(
                "dst_port",
                event.get(
                    "ingress_port",
                    80 if raw_protocol == "http" else 0
                )
            )
        )
    )
    if raw_protocol == "http" and dst_port == 0:
        dst_port = 80

    protocol = _infer_protocol(raw_protocol, dst_port)
    ingress_port = _infer_ingress_port(protocol, dst_port)

    path = _norm_text(event.get("path") or event.get("request_path") or event.get("rtsp_path"))
    payload = _norm_text(event.get("payload") or event.get("body") or event.get("close_reason"))
    user_agent = _norm_text(event.get("user_agent"))
    method = _norm_text(event.get("method"))
    event_type = _norm_text(event.get("event_type"))
    topic = _norm_text(event.get("topic"))
    command = _norm_text(event.get("command"))
    username = _norm_text(event.get("username"))
    password = _norm_text(event.get("password"))

    # Fallback HTTP method from payload if needed
    if not method and payload:
        parts = payload.split()
        if parts:
            maybe_method = parts[0].upper()
            if maybe_method in HTTP_METHODS:
                method = maybe_method.lower()

    return {
        "protocol": protocol,
        "dst_port": dst_port,
        "ingress_port": ingress_port,
        "path": path,
        "payload": payload,
        "user_agent": user_agent,
        "method": method,
        "event_type": event_type,
        "topic": topic,
        "command": command,
        "close_reason": _norm_text(event.get("close_reason")),
        "username": username,
        "password": password,
        "status_code": _safe_int(event.get("status_code", event.get("response_status", 0))),
        "requests_per_min": _safe_float(event.get("requests_per_min", 0)),
        "total_events": _safe_int(event.get("total_events", 0)),
        "has_exploit": _safe_int(event.get("has_exploit", 0)),
        "scanner_path_hits": _safe_int(event.get("scanner_path_hits", 0)),
        "file_download_count": _safe_int(event.get("file_download_count", 0)),
        "unique_protocols": _safe_int(event.get("unique_protocols", 0)),
        "login_attempts": _safe_int(event.get("login_attempts", 0)),
        "login_successes": _safe_int(event.get("login_successes", 0)),
        "unique_usernames": _safe_int(event.get("unique_usernames", 0)),
        "unique_passwords": _safe_int(event.get("unique_passwords", 0)),
        "command_count": _safe_int(event.get("command_count", 0)),
    }


# -----------------------------
# Protocol-specific rules
# -----------------------------
def _evaluate_http(fields, ip_state, session_state=None):
    reasons = []
    score = 0
    session_state = session_state or {}

    path = fields["path"]
    payload = fields["payload"]
    user_agent = fields["user_agent"]
    method = fields["method"]
    requests_per_min = fields["requests_per_min"]
    total_events = fields["total_events"]
    has_exploit = fields["has_exploit"]
    scanner_path_hits = fields["scanner_path_hits"]
    file_download_count = fields["file_download_count"]
    unique_protocols = fields["unique_protocols"]
    suspicious_count = _safe_int(session_state.get("suspicious_count", 0))

    if fields["dst_port"] in HTTP_BACKEND_PORTS:
        reasons.append(f"http_backend_port_seen:{fields['dst_port']}")

    if _is_scanner_path(path):
        reasons.append("known_scanner_path")
        score += 3

    if _contains_any(path, ("../", "..\\", "/etc/passwd", "/etc/shadow")):
        reasons.append("path_traversal_attempt")
        score += 4

    if payload and _contains_any(payload, EXPLOIT_STRINGS):
        reasons.append("exploit_string_in_payload")
        score += 4

    if has_exploit == 1:
        reasons.append("has_exploit_feature")
        score += 3

    if scanner_path_hits > 0:
        reasons.append("scanner_path_hits_feature")
        score += 2

    if user_agent and _contains_any(user_agent, BAD_USER_AGENTS):
        reasons.append("suspicious_user_agent")
        score += 2

        # Safe paths should not bypass routing when they are requested by
        # obviously script-driven clients such as curl or requests.
        if _is_safe_path(path):
            reasons.append("suspicious_tooling_on_safe_path")
            score += 1

    if user_agent and _contains_any(user_agent, GOOD_BOTS):
        reasons.append("known_good_bot")
        score -= 1

    if method in {"delete", "patch"} and path.startswith("/api/"):
        reasons.append("sensitive_http_method")
        score += 1

    if requests_per_min >= 60:
        reasons.append("high_request_rate")
        score += 2

    if total_events >= 100:
        reasons.append("high_total_events")
        score += 2

    if unique_protocols > 1:
        reasons.append("multiple_protocols_touched")
        score += 1

    if file_download_count > 0:
        reasons.append("file_download_activity")
        score += 2

    strong_attack = any(
        reason in reasons
        for reason in (
            "known_scanner_path",
            "path_traversal_attempt",
            "exploit_string_in_payload",
            "has_exploit_feature",
        )
    )

    if _is_safe_path(path) and not strong_attack and not reasons and requests_per_min < 60:
        return "real", ["normal_http_path"], 0

    if path.startswith("/api/") and not strong_attack:
        if method in {"get", "post", "put"} and not (
            user_agent and _contains_any(user_agent, BAD_USER_AGENTS)
        ):
            return "real", ["normal_api_path"], max(score, 0)

    if suspicious_count >= 2 and score >= 2:
        reasons.append("repeat_suspicious_session")
        score += 2

    if score >= 3:
        return "honeypot", reasons, score

    if not reasons:
        return "real", ["no_rule_triggered"], 0

    return "real", reasons, score


def _evaluate_ssh(fields, ip_state):
    reasons = []
    score = 0

    event_type = fields["event_type"]
    payload = fields["payload"]
    command = fields["command"]
    requests_per_min = fields["requests_per_min"]
    total_events = fields["total_events"]
    has_exploit = fields["has_exploit"]
    file_download_count = fields["file_download_count"]
    login_attempts = fields["login_attempts"]
    login_successes = fields["login_successes"]
    unique_usernames = fields["unique_usernames"]
    unique_passwords = fields["unique_passwords"]
    command_count = fields["command_count"]
    suspicious_count = _safe_int(ip_state.get("suspicious_count", 0))

    # No legitimate user reaches this honeypot over SSH, so every SSH packet is
    # untrusted from the first connection. Scoring the bare connection above the
    # honeypot threshold flags the source on packet one; the session-timeout
    # window then keeps the whole source on the honeypot instead of letting a
    # later packet flip it back to "real". The specific rules below add severity
    # signal that the ML classifier uses to rate the session.
    reasons.append("ssh_untrusted_connection")
    score += 3

    if event_type in SSH_SUSPICIOUS_EVENT_TYPES:
        reasons.append("ssh_failed_auth")
        score += 3

    if login_attempts >= 3 or unique_usernames >= 3 or unique_passwords >= 3:
        reasons.append("ssh_bruteforce_pattern")
        score += 3

    if command and _contains_any(command, SSH_SUSPICIOUS_COMMANDS):
        reasons.append("ssh_suspicious_command")
        score += 4

    if payload and _contains_any(payload, EXPLOIT_STRINGS):
        reasons.append("exploit_string_in_payload")
        score += 4

    if has_exploit == 1:
        reasons.append("has_exploit_feature")
        score += 3

    if command_count >= 5:
        reasons.append("ssh_command_burst")
        score += 2

    if file_download_count > 0:
        reasons.append("file_download_activity")
        score += 3

    if requests_per_min >= 20:
        reasons.append("high_request_rate")
        score += 2

    if total_events >= 40:
        reasons.append("high_total_events")
        score += 1

    if suspicious_count >= 2 and score >= 2:
        reasons.append("repeat_suspicious_ip")
        score += 2

    # Every SSH packet now carries the untrusted-connection base score, so this
    # always routes to the honeypot. (A successful login over SSH means the
    # attacker reached the Cowrie honeypot, which is still a honeypot route.)
    return "honeypot", reasons, score


def _evaluate_mqtt(fields, ip_state):
    reasons = []
    score = 0

    topic = fields["topic"]
    payload = fields["payload"]
    event_type = fields["event_type"]
    requests_per_min = fields["requests_per_min"]
    total_events = fields["total_events"]
    has_exploit = fields["has_exploit"]
    file_download_count = fields["file_download_count"]
    suspicious_count = _safe_int(ip_state.get("suspicious_count", 0))

    if topic and _contains_any(topic, MQTT_SUSPICIOUS_TOPIC_MARKERS):
        reasons.append("mqtt_suspicious_topic")
        score += 2

    if event_type in {"subscribe", "topic_subscribed"} and _contains_any(topic, ("#", "+")):
        reasons.append("mqtt_wildcard_subscription")
        score += 2

    if payload and _contains_any(payload, EXPLOIT_STRINGS):
        reasons.append("exploit_string_in_payload")
        score += 4

    if has_exploit == 1:
        reasons.append("has_exploit_feature")
        score += 3

    if file_download_count > 0:
        reasons.append("file_download_activity")
        score += 3

    if requests_per_min >= 60:
        reasons.append("high_request_rate")
        score += 2

    if total_events >= 100:
        reasons.append("high_total_events")
        score += 2

    if suspicious_count >= 2 and score >= 2:
        reasons.append("repeat_suspicious_ip")
        score += 2

    if score >= 3:
        return "honeypot", reasons, score

    if topic and _starts_with_any(topic, MQTT_SAFE_TOPIC_PREFIXES):
        return "real", ["mqtt_normal_topic"], 0

    if event_type in {"message", "publish", "message_published"} and not reasons:
        return "real", ["mqtt_message_observed"], 0

    if not reasons:
        return "real", ["no_rule_triggered"], 0

    return "real", reasons, score


def _evaluate_rtsp(fields, ip_state):
    reasons = []
    score = 0

    path = fields["path"]
    payload = fields["payload"]
    close_reason = fields["close_reason"]
    event_type = fields["event_type"]
    requests_per_min = fields["requests_per_min"]
    total_events = fields["total_events"]
    has_exploit = fields["has_exploit"]
    suspicious_count = _safe_int(ip_state.get("suspicious_count", 0))

    if path and _contains_any(path, RTSP_SUSPICIOUS_PATH_MARKERS):
        reasons.append("rtsp_suspicious_path")
        score += 3

    if close_reason and _contains_any(close_reason, RTSP_SUSPICIOUS_CLOSE_REASONS):
        reasons.append("rtsp_suspicious_close_reason")
        score += 3

    if payload and _contains_any(payload, EXPLOIT_STRINGS):
        reasons.append("exploit_string_in_payload")
        score += 4

    if has_exploit == 1:
        reasons.append("has_exploit_feature")
        score += 3

    if requests_per_min >= 30:
        reasons.append("high_request_rate")
        score += 2

    if total_events >= 50:
        reasons.append("high_total_events")
        score += 1

    if suspicious_count >= 2 and score >= 2:
        reasons.append("repeat_suspicious_ip")
        score += 2

    if score >= 3:
        return "honeypot", reasons, score

    if event_type in {"stream_read", "session_created", "connection_opened"}:
        if path and _starts_with_any(path, RTSP_SAFE_PATH_PREFIXES):
            return "real", ["rtsp_normal_stream_path"], 0
        return "real", ["rtsp_connection_observed"], max(score, 0)

    if not reasons:
        return "real", ["no_rule_triggered"], 0

    return "real", reasons, score


# -----------------------------
# Main rule engine
# -----------------------------
def evaluate_rules(event, ip_state, session_state=None):
    """
    Returns:
        route: "real" or "honeypot"
        reasons: list[str]
        score: int
    """

    fields = build_routing_context(event)
    session_state = session_state or {}
    protocol = fields["protocol"]

    if protocol == "http":
        if bool(session_state.get("flagged", False)):
            return "honeypot", ["session_previously_flagged"], 999
        if bool(ip_state.get("http_flagged", False)):
            return "honeypot", ["ip_previously_flagged"], 999
        return _evaluate_http(fields, ip_state, session_state=session_state)

    flagged = bool(ip_state.get("flagged", False))

    if flagged:
        return "honeypot", ["ip_previously_flagged"], 999

    if protocol == "ssh":
        return _evaluate_ssh(fields, ip_state)

    if protocol == "mqtt":
        return _evaluate_mqtt(fields, ip_state)

    if protocol == "rtsp":
        return _evaluate_rtsp(fields, ip_state)

    return "real", ["unsupported_protocol"], 0


# -----------------------------
# Manual quick test
# -----------------------------
if __name__ == "__main__":
    tests = [
        {
            "source_ip": "196.153.196.92",
            "protocol": "http",
            "event_type": "request",
            "destination_port": 80,
            "path": "/admin",
            "payload": "GET /admin HTTP/1.1",
            "user_agent": "curl/7.68",
        },
        {
            "source_ip": "198.51.100.10",
            "protocol": "http",
            "event_type": "request",
            "destination_port": 80,
            "path": "/",
            "payload": "GET / HTTP/1.1",
            "user_agent": "Mozilla/5.0",
        },
        {
            "source_ip": "203.0.113.33",
            "protocol": "ssh",
            "event_type": "login_attempt",
            "destination_port": 22,
            "username": "root",
            "password": "admin",
        },
        {
            "source_ip": "203.0.113.10",
            "protocol": "mqtt",
            "event_type": "message",
            "destination_port": 1883,
            "topic": "office/sensor/temp",
            "payload": "24.3",
        },
        {
            "source_ip": "203.0.113.11",
            "protocol": "mqtt",
            "event_type": "topic_subscribed",
            "destination_port": 1883,
            "topic": "#",
        },
        {
            "source_ip": "203.0.113.12",
            "protocol": "rtsp",
            "event_type": "connection_closed",
            "destination_port": 554,
            "path": "Streaming/Channels/101",
            "close_reason": "path 'Streaming/Channels/101' is not configured",
        },
    ]

    for index, event in enumerate(tests, start=1):
        route, reasons, score = evaluate_rules(event, {})
        print(f"Test {index}")
        print("Event   :", event)
        print("Route   :", route)
        print("Reasons :", reasons)
        print("Score   :", score)
        print("-" * 60)
