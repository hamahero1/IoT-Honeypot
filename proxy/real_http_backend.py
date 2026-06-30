#!/usr/bin/env python3
"""
Safe real HTTP backend for port 28080.

This backend behaves like a small normal web app so public users on port 80 see
a believable application flow after the proxy forwards allowed traffic here.
"""

import argparse
import json
import os
import threading
from datetime import datetime, timezone
from html import escape
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


REAL_HTTP_LOG_PATH = "/opt/iot-honeypot/logs/http_real_28080.jsonl"
LOG_LOCK = threading.Lock()
APP_STATE_LOCK = threading.RLock()
APP_SESSIONS: dict[str, dict] = {}

DEVICE_CATALOG = [
    {"id": "cam-lobby-01", "name": "Lobby Camera", "status": "Online", "zone": "Entrance"},
    {"id": "door-west-02", "name": "West Door Controller", "status": "Online", "zone": "Floor 1"},
    {"id": "hvac-core-03", "name": "HVAC Core", "status": "Maintenance", "zone": "Plant Room"},
    {"id": "sensor-cold-04", "name": "Cold Room Sensor", "status": "Online", "zone": "Storage"},
]


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def append_jsonl(path, payload):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    line = json.dumps(payload, ensure_ascii=False)
    with LOG_LOCK:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def first_forwarded_ip(headers, fallback):
    forwarded = headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return fallback


def session_id_from_headers(headers):
    direct = str(headers.get("X-Session-Id") or "").strip()
    if direct:
        return direct

    raw_cookie = headers.get("Cookie", "")
    if not raw_cookie:
        return ""

    cookie = SimpleCookie()
    try:
        cookie.load(raw_cookie)
    except Exception:
        return ""

    gateway_cookie = cookie.get("gateway_sid")
    return str(gateway_cookie.value).strip() if gateway_cookie else ""


def get_app_session(session_id):
    if not session_id:
        return {
            "authenticated": False,
            "username": "",
            "display_name": "Guest",
            "role": "observer",
            "alert_mode": "monitor",
            "watchlist": [],
            "ack_count": 0,
            "last_action": "none",
            "last_seen_utc": utc_now(),
        }

    with APP_STATE_LOCK:
        session = APP_SESSIONS.setdefault(
            session_id,
            {
                "authenticated": False,
                "username": "",
                "display_name": "Guest",
                "role": "observer",
                "alert_mode": "monitor",
                "watchlist": [],
                "ack_count": 0,
                "last_action": "session_created",
                "created_utc": utc_now(),
            },
        )
        session["last_seen_utc"] = utc_now()
        return dict(session)


def update_app_session(session_id, **changes):
    if not session_id:
        return

    with APP_STATE_LOCK:
        session = APP_SESSIONS.setdefault(
            session_id,
            {
                "authenticated": False,
                "username": "",
                "display_name": "Guest",
                "role": "observer",
                "alert_mode": "monitor",
                "watchlist": [],
                "ack_count": 0,
                "last_action": "session_created",
                "created_utc": utc_now(),
            },
        )
        session.update(changes)
        session["last_seen_utc"] = utc_now()


def render_layout(title, eyebrow, body_html):
    page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{escape(title)}</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #0f1720;
      --panel: #17212b;
      --line: #243244;
      --text: #eef2f7;
      --muted: #a6b2c1;
      --accent: #5aa5ff;
      --good: #34d399;
      --warn: #f59e0b;
      --danger: #f97316;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--text);
      font-family: "Segoe UI", Tahoma, sans-serif;
    }}
    .shell {{
      width: min(1040px, calc(100% - 32px));
      margin: 0 auto;
      padding: 24px 0 36px;
    }}
    .hero {{
      display: grid;
      grid-template-columns: 1.2fr 0.8fr;
      gap: 18px;
      margin-bottom: 18px;
    }}
    .hero-card, .panel {{
      border: 1px solid var(--line);
      border-radius: 14px;
      background: var(--panel);
      box-shadow: 0 8px 24px rgba(0,0,0,.18);
      padding: 18px;
    }}
    .eyebrow {{
      display: inline-block;
      color: var(--accent);
      font-size: 12px;
      font-weight: 800;
      letter-spacing: .16em;
      text-transform: uppercase;
      margin-bottom: 8px;
    }}
    h1 {{
      margin: 0 0 10px;
      font-size: clamp(28px, 4vw, 42px);
      line-height: 1.05;
      letter-spacing: -.03em;
    }}
    p {{
      margin: 0;
      color: var(--muted);
      line-height: 1.5;
    }}
    .meta {{
      display: grid;
      gap: 10px;
    }}
    .meta div {{
      display: grid;
      gap: 4px;
      padding: 12px;
      border-radius: 12px;
      background: rgba(255,255,255,.04);
      border: 1px solid rgba(255,255,255,.06);
    }}
    .meta span {{
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .1em;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(12, 1fr);
      gap: 16px;
    }}
    .span-7 {{ grid-column: span 7; }}
    .span-5 {{ grid-column: span 5; }}
    .span-4 {{ grid-column: span 4; }}
    .span-8 {{ grid-column: span 8; }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 12px;
      margin-top: 16px;
    }}
    .stat {{
      padding: 14px;
      border-radius: 12px;
      background: rgba(255,255,255,.045);
      border: 1px solid rgba(255,255,255,.06);
    }}
    .stat span {{
      display: block;
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .1em;
      margin-bottom: 8px;
    }}
    .stat strong {{
      font-size: 26px;
      letter-spacing: -.04em;
    }}
    form {{
      display: grid;
      gap: 12px;
    }}
    label {{
      display: grid;
      gap: 6px;
      color: var(--muted);
      font-size: 13px;
      font-weight: 700;
    }}
    input, select, textarea {{
      width: 100%;
      border: 1px solid rgba(255,255,255,.08);
      border-radius: 14px;
      background: rgba(5,10,16,.95);
      color: var(--text);
      padding: 12px 13px;
      font: inherit;
    }}
    textarea {{ min-height: 90px; resize: vertical; }}
    button, .ghost-link {{
      border: 0;
      border-radius: 14px;
      padding: 12px 14px;
      font: inherit;
      font-weight: 800;
      cursor: pointer;
      text-decoration: none;
      text-align: center;
    }}
    button.primary {{
      color: #041015;
      background: linear-gradient(135deg, var(--accent), var(--good));
    }}
    button.secondary, .ghost-link {{
      color: var(--text);
      background: rgba(255,255,255,.08);
      border: 1px solid rgba(255,255,255,.08);
    }}
    .actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }}
    .device-list {{
      display: grid;
      gap: 10px;
    }}
    .device {{
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 10px;
      padding: 14px;
      border-radius: 18px;
      background: rgba(255,255,255,.045);
      border: 1px solid rgba(255,255,255,.06);
    }}
    .device small, .hint {{
      color: var(--muted);
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      width: fit-content;
      padding: 8px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 900;
      text-transform: uppercase;
      letter-spacing: .08em;
      background: rgba(52,211,153,.15);
      color: #bbf7d0;
    }}
    .status-online {{ color: #bbf7d0; }}
    .status-maintenance {{ color: #fde68a; }}
    .topnav {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-bottom: 14px;
    }}
    .topnav a {{
      color: var(--text);
      text-decoration: none;
      padding: 10px 12px;
      border-radius: 12px;
      background: rgba(255,255,255,.05);
      border: 1px solid rgba(255,255,255,.06);
    }}
    .callout {{
      margin-top: 12px;
      padding: 12px 14px;
      border-radius: 16px;
      background: rgba(56,189,248,.09);
      border: 1px solid rgba(56,189,248,.14);
      color: var(--muted);
    }}
    @media (max-width: 900px) {{
      .hero, .grid {{ grid-template-columns: 1fr; }}
      .span-7, .span-5, .span-4, .span-8 {{ grid-column: auto; }}
      .stats {{ grid-template-columns: 1fr; }}
      .device {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <main class="shell">
    {body_html}
  </main>
</body>
</html>"""
    return page.encode("utf-8")


class RealHttpHandler(BaseHTTPRequestHandler):
    server_version = "Gateway"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self._handle_request()

    def do_HEAD(self):
        self._handle_request(write_body=False)

    def do_POST(self):
        self._handle_request()

    def do_PUT(self):
        self._handle_request()

    def do_PATCH(self):
        self._handle_request()

    def do_DELETE(self):
        self._handle_request()

    def do_OPTIONS(self):
        body = b""
        self.send_response(204)
        self.send_header("Allow", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()
        self._write_log(status_code=204, response_bytes=len(body))

    def _handle_request(self, write_body=True):
        split = urlsplit(self.path)
        path = split.path or "/"
        session_id = session_id_from_headers(self.headers)
        app_session = get_app_session(session_id)

        if path == "/health":
            self._send_json(
                200,
                {
                    "status": "ok",
                    "service": "real_http_backend",
                    "session_id": session_id or None,
                    "authenticated": bool(app_session.get("authenticated")),
                },
                write_body=write_body,
            )
            return

        if path == "/favicon.ico":
            self._send_bytes(204, b"", "image/x-icon", write_body=write_body)
            return

        if path == "/" and self.command == "GET":
            if app_session.get("authenticated"):
                self._redirect("/home")
                return
            self._send_html(200, self._render_landing(app_session), write_body=write_body)
            return

        if path == "/home" and self.command == "GET":
            if not app_session.get("authenticated"):
                self._redirect("/")
                return
            self._send_html(200, self._render_home(app_session), write_body=write_body)
            return

        if path == "/products" and self.command == "GET":
            if not app_session.get("authenticated"):
                self._redirect("/")
                return
            self._send_html(200, self._render_products(app_session), write_body=write_body)
            return

        if path == "/api/v1/profile" and self.command == "GET":
            if not app_session.get("authenticated"):
                self._send_json(401, {"error": "unauthorized"}, write_body=write_body)
                return
            self._send_json(
                200,
                {
                    "session_id": session_id,
                    "username": app_session.get("username"),
                    "display_name": app_session.get("display_name"),
                    "role": app_session.get("role"),
                    "alert_mode": app_session.get("alert_mode"),
                    "watchlist": app_session.get("watchlist", []),
                    "last_action": app_session.get("last_action"),
                    "last_seen_utc": app_session.get("last_seen_utc"),
                },
                write_body=write_body,
            )
            return

        body_raw = self._read_body()
        form = self._parse_form(body_raw)

        if path == "/api/auth/login" and self.command == "POST":
            self._handle_login(session_id, form)
            return

        if path == "/api/auth/logout" and self.command == "POST":
            update_app_session(
                session_id,
                authenticated=False,
                username="",
                display_name="Guest",
                role="observer",
                watchlist=[],
                last_action="logged_out",
            )
            self._redirect("/")
            return

        if path == "/api/v1/profile" and self.command == "POST":
            if not app_session.get("authenticated"):
                self._redirect("/")
                return
            update_app_session(
                session_id,
                display_name=form.get("display_name", [app_session.get("display_name", "Operator")])[0][:60],
                alert_mode=form.get("alert_mode", [app_session.get("alert_mode", "monitor")])[0][:30],
                last_action="profile_updated",
            )
            self._redirect("/home")
            return

        if path == "/api/cart" and self.command == "POST":
            if not app_session.get("authenticated"):
                self._redirect("/")
                return
            selected_device = form.get("device_id", [""])[0][:64]
            action = form.get("action", ["watch"])[0][:32]
            watchlist = list(app_session.get("watchlist", []))
            if selected_device and action == "watch" and selected_device not in watchlist:
                watchlist.append(selected_device)
            if selected_device and action == "remove":
                watchlist = [item for item in watchlist if item != selected_device]
            ack_count = int(app_session.get("ack_count", 0)) + (1 if action == "acknowledge" else 0)
            update_app_session(
                session_id,
                watchlist=watchlist[:8],
                ack_count=ack_count,
                last_action=f"{action}:{selected_device or 'none'}",
            )
            self._redirect("/products")
            return

        self._send_bytes(404, b"Not Found", "text/plain; charset=utf-8", write_body=write_body)

    def _handle_login(self, session_id, form):
        username = form.get("username", [""])[0].strip()
        password = form.get("password", [""])[0].strip()

        if not session_id or not username or not password:
            self._send_html(400, self._render_landing(get_app_session(session_id), error="Username and password are required."))
            return

        role = "admin" if username.lower().startswith("admin") else "operator"
        update_app_session(
            session_id,
            authenticated=True,
            username=username[:40],
            display_name=username[:40].replace(".", " ").title(),
            role=role,
            alert_mode="monitor",
            last_action="logged_in",
            last_login_utc=utc_now(),
        )
        self._redirect("/home")

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

    def _parse_form(self, body_raw):
        if not body_raw:
            return {}
        text = body_raw.decode("utf-8", errors="replace")
        return parse_qs(text, keep_blank_values=True)

    def _render_landing(self, app_session, error=""):
        error_html = ""
        if error:
            error_html = f"<div class='callout'>{escape(error)}</div>"

        body = f"""
<section class="hero">
  <div class="hero-card">
    <span class="eyebrow">Welcome</span>
    <h1>Sign in</h1>
    <p>Open your workspace and continue where you left off.</p>
    <div class="stats">
      <div class="stat"><span>Devices</span><strong>24</strong></div>
      <div class="stat"><span>Alerts</span><strong>3</strong></div>
      <div class="stat"><span>Team</span><strong>7</strong></div>
    </div>
    <div class="callout">Use your account to continue.</div>
  </div>
  <div class="hero-card">
    <span class="eyebrow">Account</span>
    <h1 style="font-size:32px">Access</h1>
    <p>Enter your username and password.</p>
    {error_html}
    <form method="POST" action="/api/auth/login">
      <label>Username
        <input name="username" placeholder="operator.a" autocomplete="username" />
      </label>
      <label>Password
        <input name="password" type="password" placeholder="password" autocomplete="current-password" />
      </label>
      <button class="primary" type="submit">Sign In</button>
    </form>
  </div>
</section>
"""
        return render_layout("Sign in", "Welcome", body)

    def _render_home(self, app_session):
        username = escape(app_session.get("display_name", "Operator"))
        role = escape(app_session.get("role", "operator"))
        last_action = escape(app_session.get("last_action", "none"))
        alert_mode = escape(app_session.get("alert_mode", "monitor"))
        ack_count = int(app_session.get("ack_count", 0))
        watchlist = list(app_session.get("watchlist", []))

        watchlist_html = "".join(
            f"<li>{escape(item)}</li>" for item in watchlist
        ) or "<li>No devices pinned yet.</li>"

        body = f"""
<nav class="topnav">
  <a href="/home">Overview</a>
  <a href="/products">Devices</a>
  <a href="/api/v1/profile">Profile API</a>
</nav>
<section class="hero">
  <div class="hero-card">
    <span class="eyebrow">Overview</span>
    <h1>Welcome back, {username}</h1>
    <p>Check your devices and update your profile.</p>
    <div class="stats">
      <div class="stat"><span>Role</span><strong>{role}</strong></div>
      <div class="stat"><span>Alert Mode</span><strong>{alert_mode}</strong></div>
      <div class="stat"><span>Acknowledged</span><strong>{ack_count}</strong></div>
    </div>
  </div>
  <div class="hero-card">
    <span class="eyebrow">Session</span>
    <div class="meta">
      <div><span>Operator</span><strong>{username}</strong></div>
      <div><span>Status</span><strong>Authenticated</strong></div>
      <div><span>Last Action</span><strong>{last_action}</strong></div>
    </div>
  </div>
</section>
<section class="grid">
  <article class="panel span-7">
    <span class="eyebrow">Profile</span>
    <form method="POST" action="/api/v1/profile">
      <label>Display Name
        <input name="display_name" value="{username}" />
      </label>
      <label>Alert Mode
        <select name="alert_mode">
          <option value="monitor"{" selected" if alert_mode == "monitor" else ""}>Monitor</option>
          <option value="review"{" selected" if alert_mode == "review" else ""}>Review</option>
          <option value="escalate"{" selected" if alert_mode == "escalate" else ""}>Escalate</option>
        </select>
      </label>
      <div class="actions">
        <button class="primary" type="submit">Save</button>
        <a class="ghost-link" href="/products">Open Devices</a>
      </div>
    </form>
  </article>
  <article class="panel span-5">
    <span class="eyebrow">Saved Devices</span>
    <p class="hint">Saved items stay here for this session.</p>
    <ul>{watchlist_html}</ul>
    <form method="POST" action="/api/auth/logout">
      <button class="secondary" type="submit">Sign Out</button>
    </form>
  </article>
</section>
"""
        return render_layout("Home", "Session", body)

    def _render_products(self, app_session):
        watchlist = list(app_session.get("watchlist", []))
        devices_html = []
        for device in DEVICE_CATALOG:
            device_id = escape(device["id"])
            watch_action = "remove" if device["id"] in watchlist else "watch"
            watch_label = "Remove" if watch_action == "remove" else "Save"
            status_class = "status-maintenance" if device["status"] == "Maintenance" else "status-online"
            devices_html.append(
                f"""
<div class="device">
  <div>
    <strong>{escape(device["name"])}</strong>
    <small>{escape(device["zone"])} · {escape(device["id"])}</small>
    <div class="badge {status_class}">{escape(device["status"])}</div>
  </div>
  <form method="POST" action="/api/cart">
    <input type="hidden" name="device_id" value="{device_id}" />
    <div class="actions">
      <button class="primary" type="submit" name="action" value="{watch_action}">{watch_label}</button>
      <button class="secondary" type="submit" name="action" value="acknowledge">Acknowledge</button>
    </div>
  </form>
</div>
"""
            )

        body = f"""
<nav class="topnav">
  <a href="/home">Overview</a>
  <a href="/products">Devices</a>
  <a href="/api/v1/profile">Profile API</a>
</nav>
<section class="hero">
  <div class="hero-card">
    <span class="eyebrow">Devices</span>
    <h1>Your devices</h1>
    <p>Review status and update saved items.</p>
  </div>
  <div class="hero-card">
    <span class="eyebrow">Today</span>
    <div class="meta">
      <div><span>Open Devices</span><strong>{len(DEVICE_CATALOG)}</strong></div>
      <div><span>Watched Devices</span><strong>{len(watchlist)}</strong></div>
      <div><span>Acknowledged</span><strong>{int(app_session.get("ack_count", 0))}</strong></div>
    </div>
  </div>
</section>
<section class="panel">
    <span class="eyebrow">List</span>
  <div class="device-list">
    {''.join(devices_html)}
  </div>
</section>
"""
        return render_layout("Devices", "List", body)

    def _send_html(self, status_code, body, write_body=True):
        self._send_bytes(status_code, body, "text/html; charset=utf-8", write_body=write_body)

    def _send_json(self, status_code, payload, write_body=True):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send_bytes(status_code, body, "application/json; charset=utf-8", write_body=write_body)

    def _send_bytes(self, status_code, body, content_type, write_body=True):
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if write_body and self.command != "HEAD":
            self.wfile.write(body)
        self._write_log(status_code=status_code, response_bytes=len(body))

    def _redirect(self, location):
        body = b""
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()
        self._write_log(status_code=303, response_bytes=len(body))

    def _write_log(self, status_code, response_bytes):
        append_jsonl(
            REAL_HTTP_LOG_PATH,
            {
                "timestamp_utc": utc_now(),
                "source_ip": first_forwarded_ip(self.headers, self.client_address[0]),
                "method": self.command,
                "path": self.path,
                "status_code": status_code,
                "response_bytes": response_bytes,
                "user_agent": self.headers.get("User-Agent"),
                "request_id": self.headers.get("X-Request-Id"),
                "session_id": self.headers.get("X-Session-Id"),
                "decision_id": self.headers.get("X-Decision-Id"),
                "route_decision": self.headers.get("X-Route-Decision"),
                "routed_to": self.headers.get("X-Routed-To"),
                "backend_port": self.headers.get("X-Backend-Port"),
            },
        )

    def log_message(self, format_string, *args):
        print(
            f"[real_http] {self.address_string()} - "
            f"{self.log_date_time_string()} {format_string % args}",
            flush=True,
        )


def parse_args():
    parser = argparse.ArgumentParser(description="Safe real HTTP backend web app")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=28080)
    return parser.parse_args()


def main():
    args = parse_args()
    server = ThreadingHTTPServer((args.listen_host, args.listen_port), RealHttpHandler)
    server.daemon_threads = True

    print("Real HTTP backend started", flush=True)
    print(f"  listen      : {args.listen_host}:{args.listen_port}", flush=True)
    print(f"  request log : {REAL_HTTP_LOG_PATH}", flush=True)
    print("  mode        : interactive mock web app", flush=True)
    print("  stop        : Ctrl+C", flush=True)

    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print("Real HTTP backend stopped", flush=True)


if __name__ == "__main__":
    main()
