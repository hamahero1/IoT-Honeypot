#!/usr/bin/env python3
"""
Inline HTTP decision proxy.

Flow:
Internet request -> this proxy (ingress 80 label) -> SessionRouter decision
-> forward to real backend (28080) or honeypot backend (8080).
"""

import argparse
import http.client
import json
import os
import sys
import threading
import time
import traceback
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4


CURRENT_DIR = Path(__file__).resolve().parent
ROUTER_DIR = CURRENT_DIR.parent
if str(ROUTER_DIR) not in sys.path:
    sys.path.insert(0, str(ROUTER_DIR))

from session_router import SessionRouter  # noqa: E402


INGRESS_HTTP_LOG_PATH = os.environ.get("ROUTER_INGRESS_HTTP_LOG_PATH", "/opt/iot-honeypot/logs/http_ingress_80.jsonl")
DEFAULT_SESSION_COOKIE_NAME = os.environ.get("ROUTER_SESSION_COOKIE_NAME", "gateway_sid")
DEFAULT_SESSION_TTL_SECONDS = int(os.environ.get("ROUTER_SESSION_TTL_SECONDS", "1800"))
HOP_BY_HOP_HEADERS = {
    "connection",
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "trailers",
}
RESPONSE_HEADERS_TO_STRIP = HOP_BY_HOP_HEADERS | {"content-length", "server", "date"}
MAX_LOG_BODY_BYTES = 8192
LOG_LOCK = threading.Lock()

_QUIET_ERRORS = (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        if sys.exc_info()[0] in _QUIET_ERRORS:
            return
        print(f"[proxy] unexpected error from {client_address}:", flush=True)
        traceback.print_exc()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def _clip_text(value, max_len=MAX_LOG_BODY_BYTES):
    text = value or ""
    if len(text) <= max_len:
        return text
    return f"{text[:max_len]}...<truncated>"


def append_jsonl(path, payload):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    line = json.dumps(payload, ensure_ascii=False)
    with LOG_LOCK:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def build_session_id():
    return f"gs-{uuid4().hex}"


def normalize_session_id(value):
    session_id = str(value or "").strip()
    if not session_id or len(session_id) > 128:
        return ""

    for char in session_id:
        if not (char.isalnum() or char in "-_."):
            return ""

    return session_id


def decode_body(raw_bytes, content_type):
    if not raw_bytes:
        return ""

    charset = "utf-8"
    if content_type:
        lower_content_type = content_type.lower()
        if "charset=" in lower_content_type:
            charset = lower_content_type.split("charset=", 1)[1].split(";")[0].strip()

    try:
        return raw_bytes.decode(charset, errors="replace")
    except Exception:
        return raw_bytes.decode("utf-8", errors="replace")


class HttpDecisionProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Gateway"
    sys_version = ""

    def do_GET(self):
        self._handle_request()

    def do_POST(self):
        self._handle_request()

    def do_PUT(self):
        self._handle_request()

    def do_PATCH(self):
        self._handle_request()

    def do_DELETE(self):
        self._handle_request()

    def do_OPTIONS(self):
        self._handle_request()

    def do_HEAD(self):
        self._handle_request()

    def _handle_request(self):
        started = time.monotonic()

        method = self.command.upper()
        split_path = urlsplit(self.path)
        request_path = split_path.path or "/"
        query_string = split_path.query or ""

        client_ip = self._extract_client_ip()
        user_agent = self.headers.get("User-Agent", "")
        content_type = self.headers.get("Content-Type", "")

        request_id = self.headers.get("X-Request-Id") or f"req-{uuid4()}"
        session_id, should_set_session_cookie = self._resolve_session_id()

        body_raw = self._read_body()
        body_text = decode_body(body_raw, content_type)
        payload = f"{method} {request_path}"
        if body_text:
            payload = f"{payload}\n{_clip_text(body_text)}"

        router_event = {
            "request_id": request_id,
            "session_id": session_id,
            "source_ip": client_ip,
            "protocol": "http",
            "event_type": "request",
            "ingress_port": self.server.ingress_port_label,
            "destination_port": self.server.ingress_port_label,
            "method": method,
            "path": request_path,
            "query_string": query_string,
            "user_agent": user_agent,
            "payload": payload,
            "body": _clip_text(body_text),
        }

        decision = self.server.router.decide(router_event)
        backend_host, backend_port = self._pick_backend(decision)

        error_text = None
        backend_status = 502
        backend_reason = "Bad Gateway"
        backend_headers = []
        backend_body = b""

        try:
            backend_status, backend_reason, backend_headers, backend_body = self._forward_to_backend(
                backend_host=backend_host,
                backend_port=backend_port,
                body_raw=body_raw,
                request_id=request_id,
                session_id=session_id,
                decision=decision,
            )
        except Exception as exc:
            error_text = str(exc)
            backend_body = json.dumps(
                {
                    "error": "backend_forward_failed",
                    "details": error_text,
                    "request_id": request_id,
                    "decision_id": decision.get("decision_id"),
                }
            ).encode("utf-8")
            backend_headers = [("Content-Type", "application/json; charset=utf-8")]

        self.send_response(backend_status, backend_reason)
        for key, value in backend_headers:
            low_key = key.lower()
            if low_key in RESPONSE_HEADERS_TO_STRIP:
                continue
            self.send_header(key, value)

        self.send_header("Content-Length", str(len(backend_body)))
        if should_set_session_cookie:
            self.send_header("Set-Cookie", self._build_session_cookie(session_id))
        for key, value in self._public_route_headers(decision, request_id, session_id):
            self.send_header(key, value)
        self.end_headers()

        if method != "HEAD":
            self.wfile.write(backend_body)

        elapsed_ms = round((time.monotonic() - started) * 1000, 2)
        self._write_ingress_log(
            request_id=request_id,
            session_id=session_id,
            source_ip=client_ip,
            method=method,
            path=request_path,
            query_string=query_string,
            user_agent=user_agent,
            body_text=body_text,
            decision=decision,
            backend_host=backend_host,
            backend_port=backend_port,
            backend_status=backend_status,
            elapsed_ms=elapsed_ms,
            error_text=error_text,
        )

    def _public_route_headers(self, decision, request_id, session_id):
        if getattr(self.server, "expose_debug_headers", False):
            return [
                ("X-Request-Id", request_id),
                ("X-Session-Id", session_id),
                ("X-Decision-Id", decision.get("decision_id", "")),
                ("X-Route-Decision", decision.get("route_decision", "")),
                ("X-Routed-To", decision.get("routed_to", "")),
            ]
        if getattr(self.server, "expose_honeypot_headers", False):
            if decision.get("route_decision") == "honeypot":
                return [
                    ("X-Route-Decision", decision.get("route_decision", "")),
                    ("X-Routed-To", decision.get("routed_to", "")),
                ]
        return []

    def _read_body(self):
        content_length = self.headers.get("Content-Length")
        if not content_length:
            return b""

        try:
            raw_len = int(content_length)
        except ValueError:
            return b""

        if raw_len <= 0:
            return b""
        return self.rfile.read(raw_len)

    def _resolve_session_id(self):
        header_session_id = normalize_session_id(self.headers.get("X-Session-Id"))
        if header_session_id:
            return header_session_id, False

        cookie_session_id = self._extract_cookie_session_id()
        if cookie_session_id:
            return cookie_session_id, False

        return build_session_id(), True

    def _extract_cookie_session_id(self):
        raw_cookie = self.headers.get("Cookie", "")
        if not raw_cookie:
            return ""

        cookie = SimpleCookie()
        try:
            cookie.load(raw_cookie)
        except Exception:
            return ""

        morsel = cookie.get(self.server.session_cookie_name)
        if not morsel:
            return ""

        return normalize_session_id(morsel.value)

    def _build_session_cookie(self, session_id):
        return (
            f"{self.server.session_cookie_name}={session_id}; "
            "Path=/; HttpOnly; SameSite=Lax"
        )

    def _extract_client_ip(self):
        forwarded = self.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0]

    def _pick_backend(self, decision):
        if decision.get("route_decision") == "honeypot":
            return self.server.honeypot_host, int(self.server.honeypot_port)
        return self.server.real_host, int(self.server.real_port)

    def _forward_to_backend(
        self,
        backend_host,
        backend_port,
        body_raw,
        request_id,
        session_id,
        decision,
    ):
        headers = {}
        for key, value in self.headers.items():
            if key.lower() in HOP_BY_HOP_HEADERS:
                continue
            headers[key] = value

        existing_forwarded = headers.get("X-Forwarded-For")
        if existing_forwarded:
            headers["X-Forwarded-For"] = f"{existing_forwarded}, {self.client_address[0]}"
        else:
            headers["X-Forwarded-For"] = self.client_address[0]

        headers["X-Forwarded-Proto"] = "http"
        headers["X-Request-Id"] = request_id
        headers["X-Session-Id"] = session_id
        headers["X-Decision-Id"] = decision.get("decision_id", "")
        headers["X-Route-Decision"] = decision.get("route_decision", "")
        headers["X-Routed-To"] = decision.get("routed_to", "")
        headers["X-Backend-Port"] = str(decision.get("backend_port") or backend_port)

        connection = http.client.HTTPConnection(
            host=backend_host,
            port=int(backend_port),
            timeout=float(self.server.backend_timeout),
        )
        try:
            connection.request(
                method=self.command.upper(),
                url=self.path,
                body=body_raw or None,
                headers=headers,
            )
            response = connection.getresponse()
            response_body = response.read()
            response_headers = response.getheaders()
            return response.status, response.reason, response_headers, response_body
        finally:
            connection.close()

    def _write_ingress_log(
        self,
        request_id,
        session_id,
        source_ip,
        method,
        path,
        query_string,
        user_agent,
        body_text,
        decision,
        backend_host,
        backend_port,
        backend_status,
        elapsed_ms,
        error_text,
    ):
        append_jsonl(
            INGRESS_HTTP_LOG_PATH,
            {
                "timestamp_utc": utc_now(),
                "request_id": request_id,
                "session_id": session_id,
                "decision_id": decision.get("decision_id"),
                "source_ip": source_ip,
                "protocol": "http",
                "event_type": "ingress_request",
                "ingress_port": int(self.server.ingress_port_label),
                "destination_port": int(self.server.ingress_port_label),
                "method": method,
                "path": path,
                "query_string": query_string,
                "user_agent": user_agent,
                "payload": _clip_text(body_text),
                "route_decision": decision.get("route_decision"),
                "routed_to": decision.get("routed_to"),
                "backend_port": decision.get("backend_port"),
                "decision_score": decision.get("score"),
                "decision_reason": decision.get("reason"),
                "log_bucket": decision.get("log_bucket"),
                "next_stage": decision.get("next_stage"),
                "forwarded_backend": f"{backend_host}:{backend_port}",
                "response_status": backend_status,
                "proxy_latency_ms": elapsed_ms,
                "error": error_text,
            },
        )

    def log_message(self, format_string, *args):
        # Keep runtime output concise.
        print(
            f"[proxy] {self.address_string()} - "
            f"{self.log_date_time_string()} {format_string % args}",
            flush=True,
        )


def parse_args():
    parser = argparse.ArgumentParser(description="HTTP ingress decision proxy (port 80 -> 8080/28080)")
    parser.add_argument("--listen-host", default=os.environ.get("ROUTER_PROXY_HOST", "0.0.0.0"))
    parser.add_argument("--listen-port", type=int, default=int(os.environ.get("ROUTER_PROXY_PORT", "80")))
    parser.add_argument(
        "--ingress-port-label",
        type=int,
        default=int(os.environ.get("ROUTER_INGRESS_PORT_LABEL", "80")),
        help="Logical ingress port label written into decision/log metadata.",
    )
    parser.add_argument("--real-host", default=os.environ.get("REAL_HTTP_HOST", "127.0.0.1"))
    parser.add_argument("--real-port", type=int, default=int(os.environ.get("REAL_HTTP_PORT", "28080")))
    parser.add_argument("--honeypot-host", default=os.environ.get("HONEYPOT_HTTP_HOST", "127.0.0.1"))
    parser.add_argument("--honeypot-port", type=int, default=int(os.environ.get("HONEYPOT_HTTP_PORT", "8080")))
    parser.add_argument("--backend-timeout", type=float, default=float(os.environ.get("ROUTER_BACKEND_TIMEOUT", "15")))
    parser.add_argument(
        "--session-cookie-name",
        default=os.environ.get("ROUTER_SESSION_COOKIE_NAME", DEFAULT_SESSION_COOKIE_NAME),
        help="Cookie name used for HTTP session stickiness.",
    )
    parser.add_argument(
        "--session-ttl-seconds",
        type=int,
        default=int(os.environ.get("ROUTER_SESSION_TTL_SECONDS", str(DEFAULT_SESSION_TTL_SECONDS))),
        help="Server-side HTTP session inactivity timeout.",
    )
    parser.add_argument(
        "--cache-path",
        default=os.environ.get("ROUTER_STATE_CACHE_PATH", "/opt/iot-honeypot/router/state_cache.json"),
        help="Router state cache path. Tests can use a temporary file to avoid changing production state.",
    )
    parser.add_argument(
        "--expose-debug-headers",
        action="store_true",
        default=os.environ.get("ROUTER_EXPOSE_DEBUG_HEADERS", "").lower() in {"1", "true", "yes"},
        help="Expose internal routing headers in public responses. Keep disabled for normal users.",
    )
    parser.add_argument(
        "--expose-honeypot-headers",
        action="store_true",
        default=os.environ.get("ROUTER_EXPOSE_HONEYPOT_HEADERS", "").lower() in {"1", "true", "yes"},
        help="Expose internal routing headers only when the request is routed to the honeypot.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    router = SessionRouter(cache_path=args.cache_path, session_ttl_seconds=args.session_ttl_seconds)

    server = QuietThreadingHTTPServer((args.listen_host, args.listen_port), HttpDecisionProxyHandler)
    server.daemon_threads = True
    server.router = router
    server.real_host = args.real_host
    server.real_port = args.real_port
    server.honeypot_host = args.honeypot_host
    server.honeypot_port = args.honeypot_port
    server.backend_timeout = args.backend_timeout
    server.ingress_port_label = args.ingress_port_label
    server.session_cookie_name = args.session_cookie_name
    server.session_ttl_seconds = args.session_ttl_seconds
    server.expose_debug_headers = args.expose_debug_headers
    server.expose_honeypot_headers = args.expose_honeypot_headers

    print("HTTP decision proxy started", flush=True)
    print(f"  listen            : {args.listen_host}:{args.listen_port}", flush=True)
    print(f"  ingress label     : {args.ingress_port_label}", flush=True)
    print(f"  real backend      : {args.real_host}:{args.real_port}", flush=True)
    print(f"  honeypot backend  : {args.honeypot_host}:{args.honeypot_port}", flush=True)
    print(f"  session cookie    : {args.session_cookie_name}", flush=True)
    print(f"  session timeout   : {args.session_ttl_seconds}s", flush=True)
    print(f"  state cache       : {args.cache_path}", flush=True)
    print(f"  debug headers     : {'enabled' if args.expose_debug_headers else 'disabled'}", flush=True)
    print(f"  honeypot headers  : {'enabled' if args.expose_honeypot_headers else 'disabled'}", flush=True)
    print(f"  ingress log       : {INGRESS_HTTP_LOG_PATH}", flush=True)
    print("  stop              : Ctrl+C", flush=True)

    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print("HTTP decision proxy stopped", flush=True)


if __name__ == "__main__":
    main()
