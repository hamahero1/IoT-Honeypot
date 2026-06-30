"""
IoT Honeypot — Interactive HTTP Honeypot
Serves a convincing multi-page IoT device management portal.
Every interaction is logged to http_honeypot.jsonl.

Enhancements over the static build:
  * Live-looking dynamic data (uptimes tick, sensors drift, logs are relative
    to now and include the visitor's own IP).
  * Real server-side device actions (ping / restart / firmware / remove) that
    log attacker intent instead of a client-side alert().
  * A "Network Diagnostics" command-injection sink that returns believable
    ping/traceroute output and captures every injection payload.
  * A fake firmware-upload page that captures uploaded payloads.
"""
import datetime
import hashlib
import html
import json
import os
import random
import re
import time
from pathlib import Path

from flask import Flask, make_response, redirect, request

app = Flask(__name__)
# Bound uploads so a hostile client cannot exhaust container memory.
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

# Process start — used to make uptimes/metrics advance over the container's life.
PROC_START = time.time()

# ── Config ────────────────────────────────────────────────────────────────────

def _default_log():
    p = Path("/logs")
    return str(p / "http_honeypot.jsonl") if p.exists() else "/opt/iot-honeypot/logs/http_honeypot.jsonl"

LOG_FILE       = os.environ.get("LOG_PATH", _default_log())
MAX_BODY_BYTES = int(os.environ.get("MAX_LOG_BODY_BYTES", "8192"))
SESSION_COOKIE = "hpdev_session"

# Every credential combo "succeeds" — attacker gets in regardless of what they try
VALID_CREDS = {
    ("admin",         "admin"),
    ("admin",         "1234"),
    ("admin",         "password"),
    ("admin",         "admin123"),
    ("administrator", "admin"),
    ("administrator", "admin123"),
    ("root",          "root"),
    ("root",          "toor"),
    ("root",          "1234"),
    ("user",          "user"),
    ("guest",         "guest"),
    ("support",       "support"),
}

# ── Shared CSS — matches real backend's dark-blue palette exactly ─────────────

SHARED_CSS = """
:root{color-scheme:dark;--bg:#0f1720;--panel:#17212b;--line:#243244;
--text:#eef2f7;--muted:#a6b2c1;--accent:#5aa5ff;--good:#34d399;
--warn:#f59e0b;--danger:#f97316;}
*{box-sizing:border-box;}
body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);
font-family:"Segoe UI",Tahoma,sans-serif;font-size:14px;}
a{color:var(--accent);text-decoration:none;}
a:hover{text-decoration:underline;}
.eyebrow{display:inline-block;color:var(--accent);font-size:11px;
font-weight:800;letter-spacing:.16em;text-transform:uppercase;margin-bottom:6px;}
.panel{border:1px solid var(--line);border-radius:14px;background:var(--panel);
box-shadow:0 8px 24px rgba(0,0,0,.18);padding:18px;}
.badge{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;
border-radius:999px;font-size:12px;font-weight:700;}
.badge.good{background:rgba(52,211,153,.15);color:var(--good);}
.badge.warn{background:rgba(245,158,11,.15);color:var(--warn);}
.badge.danger{background:rgba(249,115,22,.15);color:var(--danger);}
.badge.info{background:rgba(90,165,255,.15);color:var(--accent);}
input,select,textarea{width:100%;border:1px solid rgba(255,255,255,.08);
border-radius:10px;background:rgba(5,10,16,.95);color:var(--text);
padding:10px 12px;font:inherit;}
button{border:0;border-radius:10px;padding:10px 16px;font:inherit;
font-weight:700;cursor:pointer;}
button.primary{color:#041015;background:linear-gradient(135deg,var(--accent),var(--good));}
button.secondary{color:var(--text);background:rgba(255,255,255,.08);
border:1px solid rgba(255,255,255,.08);}
table{width:100%;border-collapse:collapse;}
th{text-align:left;color:var(--muted);font-size:11px;letter-spacing:.1em;
text-transform:uppercase;padding:8px 12px;border-bottom:1px solid var(--line);}
td{padding:10px 12px;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:middle;}
tr:hover td{background:rgba(255,255,255,.03);}
pre,code{font-family:monospace;font-size:13px;}
pre{background:rgba(0,0,0,.35);border-radius:10px;padding:14px;
overflow:auto;color:var(--muted);}
.alert{padding:12px 16px;border-radius:10px;margin-bottom:14px;font-size:13px;}
.alert.error{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.3);color:#fca5a5;}
.alert.success{background:rgba(52,211,153,.12);border:1px solid rgba(52,211,153,.3);color:#6ee7b7;}
.layout{display:grid;grid-template-columns:220px 1fr;min-height:100vh;}
.sidebar{background:var(--panel);border-right:1px solid var(--line);
padding:20px 0;display:flex;flex-direction:column;gap:2px;}
.sidebar-brand{padding:0 20px 16px;border-bottom:1px solid var(--line);margin-bottom:12px;}
.sidebar-brand h2{margin:0;font-size:15px;letter-spacing:-.02em;}
.sidebar-brand small{color:var(--muted);font-size:11px;}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 20px;
color:var(--muted);text-decoration:none;font-size:13px;font-weight:600;
border-left:3px solid transparent;}
.nav-item:hover,.nav-item.active{color:var(--text);background:rgba(255,255,255,.04);
border-left-color:var(--accent);text-decoration:none;}
.nav-section{padding:16px 20px 4px;color:var(--muted);font-size:10px;
letter-spacing:.14em;text-transform:uppercase;}
.content{padding:28px 32px;overflow:auto;}
.page-header{margin-bottom:22px;}
.page-header h1{margin:0 0 4px;font-size:22px;letter-spacing:-.03em;}
.page-header p{margin:0;color:var(--muted);}
"""

# ── Navigation sidebar ────────────────────────────────────────────────────────

def _sidebar(active="dashboard"):
    items = [
        ("dashboard",   "🖥", "Dashboard",        "/admin/dashboard"),
        ("devices",     "📡", "Devices",          "/admin/devices"),
        ("firmware",    "🧩", "Firmware",         "/admin/firmware"),
        ("users",       "👥", "Users",            "/admin/users"),
        ("logs",        "📋", "System Logs",      "/admin/logs"),
        ("diagnostics", "🛠", "Diagnostics",      "/admin/diagnostics"),
        ("network",     "🌐", "Network",          "/admin/network"),
        ("config",      "⚙",  "Settings",         "/admin/config"),
    ]
    rows = []
    for key, icon, label, href in items:
        cls = "nav-item active" if key == active else "nav-item"
        rows.append(f'<a href="{href}" class="{cls}">{icon} {label}</a>')
    return f"""
<nav class="sidebar">
  <div class="sidebar-brand">
    <div class="eyebrow">IoT Gateway</div>
    <h2>DeviceHub Pro</h2>
    <small>Firmware v3.4.1</small>
  </div>
  <span class="nav-section">Main</span>
  {"".join(rows[0:2])}
  <span class="nav-section">Management</span>
  {"".join(rows[2:5])}
  <span class="nav-section">System</span>
  {"".join(rows[5:])}
  <div style="margin-top:auto;padding:16px 20px;border-top:1px solid var(--line);">
    <a href="/logout" class="nav-item" style="color:var(--danger);">🚪 Sign Out</a>
  </div>
</nav>"""

def _page(title, body, active="dashboard", logged_in=True):
    if logged_in:
        inner = f'<div class="layout">{_sidebar(active)}<div class="content">{body}</div></div>'
    else:
        inner = body
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"/>'
            f'<meta name="viewport" content="width=device-width,initial-scale=1"/>'
            f'<title>{title} — DeviceHub Pro</title>'
            f'<style>{SHARED_CSS}</style></head><body>{inner}</body></html>')

# ── Fake data ─────────────────────────────────────────────────────────────────
# up_s = uptime in seconds at process boot; advances live via _uptime(). None = offline.

DEVICES = [
    {"id":"DEV-001","name":"Gateway Node Alpha",  "ip":"10.0.1.1",  "mac":"AA:BB:CC:11:22:01","type":"Gateway", "status":"online", "up_s":1231200,"fw":"3.4.1"},
    {"id":"DEV-002","name":"Sensor Hub Corridor", "ip":"10.0.1.12", "mac":"AA:BB:CC:11:22:02","type":"Sensor",  "status":"online", "up_s":568800, "fw":"2.1.0"},
    {"id":"DEV-003","name":"Cam Unit West",        "ip":"10.0.1.20", "mac":"AA:BB:CC:11:22:03","type":"Camera", "status":"online", "up_s":1904400,"fw":"4.0.2"},
    {"id":"DEV-004","name":"MQTT Broker Primary",  "ip":"10.0.1.30", "mac":"AA:BB:CC:11:22:04","type":"Broker", "status":"online", "up_s":1231200,"fw":"5.1.3"},
    {"id":"DEV-005","name":"Sensor Hub East",      "ip":"10.0.1.45", "mac":"AA:BB:CC:11:22:05","type":"Sensor", "status":"warning","up_s":97200,  "fw":"2.0.9"},
    {"id":"DEV-006","name":"Edge Compute Unit",    "ip":"10.0.1.50", "mac":"AA:BB:CC:11:22:06","type":"Compute","status":"online", "up_s":324000, "fw":"1.9.7"},
    {"id":"DEV-007","name":"Cam Unit North",       "ip":"10.0.1.22", "mac":"AA:BB:CC:11:22:07","type":"Camera", "status":"offline","up_s":None,   "fw":"4.0.1"},
    {"id":"DEV-008","name":"Relay Board B2",       "ip":"10.0.1.88", "mac":"AA:BB:CC:11:22:08","type":"Relay",  "status":"online", "up_s":817200, "fw":"1.3.0"},
]

USERS = [
    {"id":1,"username":"admin",       "role":"Administrator","email":"admin@internal.local",   "last_login":"2026-05-17 08:42:11","active":True},
    {"id":2,"username":"operator",    "role":"Operator",     "email":"ops@internal.local",      "last_login":"2026-05-16 22:10:05","active":True},
    {"id":3,"username":"viewer",      "role":"Read-Only",    "email":"view@internal.local",     "last_login":"2026-05-15 14:33:27","active":True},
    {"id":4,"username":"svc_monitor", "role":"Service",      "email":"monitor@internal.local",  "last_login":"2026-05-17 09:01:00","active":True},
    {"id":5,"username":"backup_user", "role":"Read-Only",    "email":"backup@internal.local",   "last_login":"2026-04-30 03:00:00","active":False},
]

# (delta_seconds_ago, level, source, message-template). {ip} is filled with the visitor IP.
LOG_TEMPLATES = [
    (8,     "INFO", "Auth",     "Successful login: admin from {ip}"),
    (44,    "INFO", "System",   "Snapshot cache refreshed (15 devices)"),
    (96,    "INFO", "Network",  "Session established from {ip}"),
    (152,   "INFO", "Auth",     "Successful login: operator from 10.0.0.4"),
    (240,   "WARN", "Device",   "DEV-005 heartbeat missed — checking status"),
    (388,   "INFO", "Network",  "DHCP lease renewed for DEV-006"),
    (515,   "INFO", "Firmware", "DEV-003 firmware check: up to date (4.0.2)"),
    (734,   "INFO", "Auth",     "Successful login: admin from 10.0.0.2"),
    (905,   "ERROR","Device",   "DEV-007 connection timeout — marked offline"),
    (1180,  "INFO", "System",   "Scheduled config backup completed"),
    (1620,  "INFO", "System",   "Daily diagnostics passed (8/8 checks OK)"),
    (2240,  "WARN", "Auth",     "Failed login attempt from 45.83.91.12 (admin)"),
    (3015,  "INFO", "Firmware", "Firmware update check scheduled for 03:00"),
    (3760,  "WARN", "Network",  "High packet rate from 45.83.91.12 — throttled"),
    (4400,  "INFO", "Device",   "DEV-005 firmware update started (2.0.9→2.1.0)"),
]

FAKE_ENV = """\
APP_ENV=production
APP_DEBUG=false
DB_HOST=10.0.1.100
DB_PORT=5432
DB_NAME=devhub_prod
DB_USER=devhub_app
DB_PASSWORD=Pr0d$eCr3t!2024
SECRET_KEY=f8a2e1d9b7c4f3a0e6d5c2b1a8f7e4d3
JWT_SECRET=9b3f2a1e8d7c6b5a4f3e2d1c0b9a8f7e
REDIS_HOST=10.0.1.101
REDIS_PORT=6379
REDIS_PASSWORD=r3d1sS3cr3t!
MQTT_BROKER=10.0.1.30
MQTT_PORT=1883
MQTT_USER=mqtt_svc
MQTT_PASSWORD=Mqt7$Pass2024
SMTP_HOST=smtp.internal.local
SMTP_PORT=587
SMTP_USER=noreply@internal.local
SMTP_PASSWORD=Sm7p$2024!
ADMIN_EMAIL=admin@internal.local
LOG_LEVEL=INFO
SESSION_LIFETIME=3600
"""

FAKE_GIT_CONFIG = """\
[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = git@gitlab.internal.local:platform/devhub-backend.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
[user]
\tname = DevHub CI
\temail = ci@internal.local
"""

FAKE_ROBOTS = """\
User-agent: *
Disallow: /admin/
Disallow: /admin/config
Disallow: /admin/users
Disallow: /admin/logs
Disallow: /admin/firmware
Disallow: /admin/diagnostics
Disallow: /api/
Disallow: /.env
Disallow: /.git/
Disallow: /backup/
Disallow: /config.php
Disallow: /db_export/
Disallow: /internal/
"""

FAKE_CONFIG_PHP = """\
<?php
// DeviceHub Pro Configuration
// DO NOT expose this file publicly

define('DB_HOST',     '10.0.1.100');
define('DB_USER',     'devhub_app');
define('DB_PASS',     'Pr0d$eCr3t!2024');
define('DB_NAME',     'devhub_prod');
define('SECRET_KEY',  'f8a2e1d9b7c4f3a0e6d5c2b1a8f7e4d3');
define('ADMIN_EMAIL', 'admin@internal.local');
define('DEBUG_MODE',  false);
define('LOG_PATH',    '/var/log/devhub/app.log');
?>
"""

SHELL_OUTPUTS = {
    "injection_ls":      "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var",
    "injection_subshell":"sh: command not found",
    "injection_backtick":"sh: permission denied",
    "injection_pipe":    "www-data\nuid=33(www-data) gid=33(www-data) groups=33(www-data)",
    "path_traversal":    "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def utc_now():
    return datetime.datetime.utcnow().isoformat() + "Z"

def real_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    return fwd.split(",")[0].strip() if fwd else request.remote_addr

def clipped_body():
    b = request.get_data(as_text=True, cache=True) or ""
    return b[:MAX_BODY_BYTES] + ("...<truncated>" if len(b) > MAX_BODY_BYTES else "")

def write_log(status, extra=None):
    entry = {
        "timestamp_utc": utc_now(),
        "ip": real_ip(),
        "method": request.method,
        "path": request.path,
        "query_string": request.query_string.decode("utf-8", errors="ignore"),
        "headers": dict(request.headers),
        "user_agent": request.headers.get("User-Agent"),
        "content_type": request.content_type,
        "content_length": request.content_length,
        "body": clipped_body(),
        "response_status": status,
        "extra": extra,
    }
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

def hp_resp(body, status=200, ctype="text/html; charset=utf-8"):
    r = make_response(body, status)
    r.headers["Content-Type"] = ctype
    r.headers["Server"] = "nginx/1.24.0"
    r.headers["X-Frame-Options"] = "SAMEORIGIN"
    r.headers["Cache-Control"] = "no-store"
    return r

def is_logged_in():
    token = request.cookies.get(SESSION_COOKIE, "")
    return bool(token) and len(token) == 32

def require_login():
    if not is_logged_in():
        return redirect(f"/login?next={request.path}")
    return None

def _session_token(username):
    return hashlib.md5(f"{username}:devhub:{utc_now()}".encode()).hexdigest()

def _detect_injection(text):
    patterns = [
        (r";\s*(ls|dir|pwd|whoami|id|cat|wget|curl|nc|bash|sh|python)", "injection_ls"),
        (r"\$\(.*?\)",  "injection_subshell"),
        (r"`[^`]+`",    "injection_backtick"),
        (r"\|+\s*(ls|cat|id|whoami|bash|sh)", "injection_pipe"),
        (r"\.\./",      "path_traversal"),
    ]
    for pat, label in patterns:
        if re.search(pat, text, re.IGNORECASE):
            return label
    return None

def _badge(status):
    if status == "online":
        return '<span class="badge good">● Online</span>'
    if status == "offline":
        return '<span class="badge danger">○ Offline</span>'
    return '<span class="badge warn">⚠ Warning</span>'

# ── Dynamic / live-looking data ───────────────────────────────────────────────

def _elapsed():
    """Seconds since this honeypot process started."""
    return time.time() - PROC_START

def _fmt_dhm(total_seconds):
    s = int(total_seconds)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, _ = divmod(s, 60)
    return f"{d}d {h}h {m}m"

def _uptime(dev):
    """Live uptime string that advances as the container runs."""
    if not dev.get("up_s"):
        return "—"
    return _fmt_dhm(dev["up_s"] + _elapsed())

def _live(seed, base, spread, ndigits=1):
    """A value that drifts around `base` but stays stable within a ~5s window,
    so repeated refreshes look like a live reading rather than a frozen page."""
    rng = random.Random(f"{seed}:{int(time.time() // 5)}")
    val = base + rng.uniform(-spread, spread)
    return round(val, ndigits) if ndigits else int(round(val))

def _device_readings(dev):
    """Believable live telemetry per device type."""
    if dev["status"] == "offline":
        return [("Status", "Unreachable")]
    t = dev["type"]
    if t == "Sensor":
        return [("Temperature", f"{_live(dev['id']+'t', 23.5, 1.2)} °C"),
                ("Humidity",    f"{_live(dev['id']+'h', 47, 4, 0)} %"),
                ("Signal",      f"-{_live(dev['id']+'s', 58, 5, 0)} dBm")]
    if t == "Camera":
        return [("Stream",   "1080p · H.264"),
                ("Framerate",f"{_live(dev['id']+'f', 25, 2, 0)} fps"),
                ("Bitrate",  f"{_live(dev['id']+'b', 4.2, 0.6)} Mbps")]
    if t == "Broker":
        return [("Connected clients", f"{_live(dev['id']+'c', 38, 5, 0)}"),
                ("Msgs/sec",          f"{_live(dev['id']+'m', 120, 25, 0)}"),
                ("CPU Load",          f"{_live(dev['id']+'l', 22, 6)} %")]
    return [("CPU Load",   f"{_live(dev['id']+'l', 18, 7)} %"),
            ("Memory",     f"{_live(dev['id']+'r', 41, 6, 0)} %"),
            ("Throughput", f"{_live(dev['id']+'n', 6.5, 1.5)} Mbps")]

def _recent_logs(ip):
    """Event log with timestamps relative to now and the visitor's IP woven in."""
    now = datetime.datetime.utcnow()
    out = []
    for delta, level, source, msg in LOG_TEMPLATES:
        ts = (now - datetime.timedelta(seconds=delta)).strftime("%Y-%m-%d %H:%M:%S")
        out.append((ts, level, source, msg.format(ip=ip)))
    return out

def _level_badge(level):
    cls = "info" if level == "INFO" else "warn" if level == "WARN" else "danger"
    return f'<span class="badge {cls}">{level}</span>'

# ── Auth routes ───────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET"])
def login_get():
    alert = ""
    if request.args.get("err") == "1":
        alert = '<div class="alert error">Invalid username or password. Please try again.</div>'
    nxt = request.args.get("next", "/admin/dashboard")
    body = f"""
<div style="min-height:100vh;display:flex;align-items:center;justify-content:center;">
  <div class="panel" style="width:min(380px,calc(100% - 32px));">
    <div class="eyebrow">DeviceHub Pro</div>
    <h1 style="margin:6px 0 4px;font-size:24px;letter-spacing:-.03em;">Sign In</h1>
    <p style="color:var(--muted);margin:0 0 20px;font-size:13px;">IoT Device Management Portal</p>
    {alert}
    <form method="POST" action="/login">
      <input type="hidden" name="next" value="{html.escape(nxt)}"/>
      <div style="display:grid;gap:10px;">
        <label style="display:grid;gap:5px;color:var(--muted);font-size:12px;font-weight:700;">
          USERNAME<input name="username" placeholder="admin" autocomplete="username" autofocus/>
        </label>
        <label style="display:grid;gap:5px;color:var(--muted);font-size:12px;font-weight:700;">
          PASSWORD<input type="password" name="password" placeholder="••••••••" autocomplete="current-password"/>
        </label>
        <button type="submit" class="primary" style="margin-top:6px;">Sign In</button>
      </div>
    </form>
    <p style="color:var(--muted);font-size:11px;margin-top:14px;text-align:center;">
      Unauthorised access is prohibited and monitored.
    </p>
  </div>
</div>"""
    write_log(200, extra={"page": "login_form"})
    return hp_resp(_page("Sign In", body, logged_in=False))

@app.route("/login", methods=["POST"])
def login_post():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    nxt      = request.form.get("next", "/admin/dashboard")
    inj      = _detect_injection(username + password)

    success = (username, password) in VALID_CREDS or (username.lower(), password) in VALID_CREDS

    write_log(302 if success else 401, extra={
        "page": "login_submit",
        "username": username,
        "password": password,
        "success": success,
        "injection_attempt": inj,
    })

    if inj:
        out = SHELL_OUTPUTS.get(inj, "command not found")
        return hp_resp(f"<pre>{out}</pre>")

    if success:
        resp = make_response(redirect(nxt))
        resp.set_cookie(SESSION_COOKIE, _session_token(username),
                        max_age=3600, httponly=True, samesite="Lax")
        resp.headers["Server"] = "nginx/1.24.0"
        return resp

    return redirect(f"/login?err=1&next={nxt}")

@app.route("/logout")
def logout():
    write_log(302, extra={"page": "logout"})
    resp = make_response(redirect("/login"))
    resp.delete_cookie(SESSION_COOKIE)
    resp.headers["Server"] = "nginx/1.24.0"
    return resp

def _landing(logged_in):
    online = sum(1 for d in DEVICES if d["status"] == "online")
    uptime = _uptime(DEVICES[0])
    cta = ('<a href="/admin/dashboard"><button class="primary" style="padding:12px 22px;font-size:14px;">Open Console →</button></a>'
           if logged_in else
           '<a href="/login"><button class="primary" style="padding:12px 22px;font-size:14px;">Sign In to Console →</button></a>')
    body = f"""
<div style="width:min(1040px,calc(100% - 32px));margin:0 auto;">
  <div style="display:flex;align-items:center;justify-content:space-between;padding:18px 0;border-bottom:1px solid var(--line);">
    <div style="display:flex;align-items:center;gap:10px;">
      <span style="font-size:22px;">🛰️</span>
      <div><strong style="font-size:16px;letter-spacing:-.02em;">DeviceHub&nbsp;Pro</strong>
        <div style="color:var(--muted);font-size:11px;">IoT Device Management Platform</div></div>
    </div>
    <div style="display:flex;align-items:center;gap:16px;">
      <a href="/admin/devices" style="font-size:13px;">Devices</a>
      <a href="/api/v1/status" style="font-size:13px;">API</a>
      <a href="/login" style="font-size:13px;">Sign In</a>
    </div>
  </div>

  <div style="display:grid;grid-template-columns:1.25fr .75fr;gap:22px;margin:34px 0;align-items:center;">
    <div>
      <div class="eyebrow">Unified Gateway · Firmware v3.4.1</div>
      <h1 style="font-size:38px;line-height:1.1;letter-spacing:-.04em;margin:6px 0 14px;">
        Every device on your network, in one console.</h1>
      <p style="color:var(--muted);font-size:15px;max-width:46ch;margin:0 0 22px;">
        Monitor sensors, cameras and brokers in real time, push firmware, and review
        access logs from a single secure dashboard.</p>
      {cta}
      <a href="/admin/devices" style="margin-left:12px;font-size:13px;">Browse device inventory →</a>
    </div>
    <div class="panel">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;">
        <span class="badge good">● All systems operational</span>
      </div>
      <table>
        <tr><td style="color:var(--muted);">Devices online</td><td><strong>{online} / {len(DEVICES)}</strong></td></tr>
        <tr><td style="color:var(--muted);">Platform</td><td>DeviceHub Pro 3.4.1</td></tr>
        <tr><td style="color:var(--muted);">Gateway uptime</td><td>{uptime}</td></tr>
        <tr><td style="color:var(--muted);">MQTT broker</td><td>10.0.1.30:1883</td></tr>
      </table>
    </div>
  </div>

  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:34px;">
    <div class="panel"><div style="font-size:20px;">📡</div>
      <strong>Device Inventory</strong>
      <p style="color:var(--muted);font-size:13px;margin:6px 0 0;">Track status, firmware and uptime across the fleet.</p></div>
    <div class="panel"><div style="font-size:20px;">📈</div>
      <strong>Live Telemetry</strong>
      <p style="color:var(--muted);font-size:13px;margin:6px 0 0;">Stream sensor, camera and broker metrics in real time.</p></div>
    <div class="panel"><div style="font-size:20px;">🔐</div>
      <strong>Access & Audit</strong>
      <p style="color:var(--muted);font-size:13px;margin:6px 0 0;">Role-based accounts with a full searchable event log.</p></div>
  </div>

  <div style="color:var(--muted);font-size:12px;padding:18px 0;border-top:1px solid var(--line);">
    © 2026 DeviceHub Pro · Unauthorised access is prohibited and monitored.
  </div>
</div>"""
    return _page("Home", body, logged_in=False)

@app.route("/", methods=["GET", "HEAD"])
@app.route("/home", methods=["GET", "HEAD"])
@app.route("/index.html", methods=["GET", "HEAD"])
def root():
    write_log(200, extra={"page": "home"})
    return hp_resp(_landing(is_logged_in()))

# ── Admin pages ───────────────────────────────────────────────────────────────

@app.route("/admin", methods=["GET", "HEAD"])
@app.route("/admin/", methods=["GET", "HEAD"])
def admin_root():
    g = require_login()
    if g: return g
    return redirect("/admin/dashboard")

@app.route("/admin/dashboard", methods=["GET"])
def admin_dashboard():
    g = require_login()
    if g: return g

    online  = sum(1 for d in DEVICES if d["status"] == "online")
    warn    = sum(1 for d in DEVICES if d["status"] == "warning")
    offline = sum(1 for d in DEVICES if d["status"] == "offline")

    dev_rows = "".join(f"""<tr>
  <td><a href="/admin/devices/{d['id']}">{d['id']}</a></td>
  <td>{d['name']}</td><td>{d['type']}</td>
  <td>{_badge(d['status'])}</td>
  <td style="color:var(--muted);">{_uptime(d)}</td>
  <td style="color:var(--muted);">{d['fw']}</td>
</tr>""" for d in DEVICES[:6])

    log_rows = "".join(f"""<tr>
  <td style="color:var(--muted);font-size:12px;white-space:nowrap;">{l[0]}</td>
  <td>{_level_badge(l[1])}</td>
  <td style="color:var(--muted);font-size:12px;">{l[2]}</td>
  <td>{l[3]}</td>
</tr>""" for l in _recent_logs(real_ip())[:5])

    # Live gateway telemetry (drifts on refresh).
    cpu  = _live("gw-cpu", 27, 8)
    mem  = _live("gw-mem", 54, 6, 0)
    thru = _live("gw-thru", 18.4, 4.0)
    sess = _live("gw-sess", 42, 6, 0)

    body = f"""
<div class="page-header">
  <div class="eyebrow">Overview</div>
  <h1>Dashboard</h1>
  <p>System status and recent activity</p>
</div>
<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:14px;">
  <div class="panel"><div style="color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em;">Total Devices</div>
    <div style="font-size:32px;font-weight:800;letter-spacing:-.05em;margin-top:6px;">{len(DEVICES)}</div></div>
  <div class="panel"><div style="color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em;">Online</div>
    <div style="font-size:32px;font-weight:800;letter-spacing:-.05em;margin-top:6px;color:var(--good);">{online}</div></div>
  <div class="panel"><div style="color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em;">Warnings</div>
    <div style="font-size:32px;font-weight:800;letter-spacing:-.05em;margin-top:6px;color:var(--warn);">{warn}</div></div>
  <div class="panel"><div style="color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em;">Offline</div>
    <div style="font-size:32px;font-weight:800;letter-spacing:-.05em;margin-top:6px;color:var(--danger);">{offline}</div></div>
</div>
<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:22px;">
  <div class="panel"><div style="color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em;">CPU Load</div>
    <div style="font-size:24px;font-weight:800;margin-top:6px;">{cpu} %</div></div>
  <div class="panel"><div style="color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em;">Memory</div>
    <div style="font-size:24px;font-weight:800;margin-top:6px;">{mem} %</div></div>
  <div class="panel"><div style="color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em;">Throughput</div>
    <div style="font-size:24px;font-weight:800;margin-top:6px;">{thru} Mbps</div></div>
  <div class="panel"><div style="color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em;">Active Sessions</div>
    <div style="font-size:24px;font-weight:800;margin-top:6px;">{sess}</div></div>
</div>
<div style="display:grid;grid-template-columns:1.4fr 1fr;gap:18px;">
  <div class="panel">
    <div style="margin-bottom:14px;"><strong>Devices</strong>
      <a href="/admin/devices" style="float:right;font-size:12px;">View all →</a></div>
    <table><thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Status</th><th>Uptime</th><th>FW</th></tr></thead>
    <tbody>{dev_rows}</tbody></table>
  </div>
  <div class="panel">
    <div style="margin-bottom:14px;"><strong>Recent Events</strong>
      <a href="/admin/logs" style="float:right;font-size:12px;">View all →</a></div>
    <table><thead><tr><th>Time</th><th>Level</th><th>Source</th><th>Message</th></tr></thead>
    <tbody>{log_rows}</tbody></table>
  </div>
</div>"""
    write_log(200, extra={"page": "admin_dashboard"})
    return hp_resp(_page("Dashboard", body, active="dashboard"))

@app.route("/admin/devices", methods=["GET"])
def admin_devices():
    g = require_login()
    if g: return g

    rows = "".join(f"""<tr>
  <td><a href="/admin/devices/{d['id']}">{d['id']}</a></td>
  <td><strong>{d['name']}</strong></td>
  <td style="color:var(--muted);">{d['ip']}</td>
  <td style="color:var(--muted);font-size:12px;">{d['mac']}</td>
  <td>{d['type']}</td>
  <td>{_badge(d['status'])}</td>
  <td style="color:var(--muted);">{_uptime(d)}</td>
  <td style="color:var(--muted);">{d['fw']}</td>
  <td><a href="/admin/devices/{d['id']}">Detail →</a></td>
</tr>""" for d in DEVICES)

    body = f"""
<div class="page-header">
  <div class="eyebrow">Inventory</div>
  <h1>Devices</h1>
  <p>All registered IoT devices on this gateway</p>
</div>
<div class="panel">
  <table><thead><tr>
    <th>ID</th><th>Name</th><th>IP</th><th>MAC</th>
    <th>Type</th><th>Status</th><th>Uptime</th><th>FW</th><th></th>
  </tr></thead><tbody>{rows}</tbody></table>
</div>"""
    write_log(200, extra={"page": "admin_devices"})
    return hp_resp(_page("Devices", body, active="devices"))

@app.route("/admin/devices/<dev_id>", methods=["GET", "POST"])
def admin_device_detail(dev_id):
    g = require_login()
    if g: return g

    dev = next((d for d in DEVICES if d["id"] == dev_id), None)
    if not dev:
        write_log(404, extra={"page": "device_detail", "dev_id": dev_id})
        return hp_resp(_page("Not Found", "<div class='panel'><h2>Device not found.</h2></div>"), 404)

    # Real server-side actions — log the attacker's intent, return a believable result.
    result = None
    if request.method == "POST":
        op = request.form.get("op", "")
        write_log(200, extra={"page": "device_action", "dev_id": dev_id,
                              "dev_ip": dev["ip"], "op": op, "form": dict(request.form)})
        result = {
            "ping":     f"PING {dev['ip']}: 4 packets transmitted, 4 received, 0% loss, avg 31.4 ms",
            "restart":  f"Restart command queued for {dev['id']} — device will reboot in ~30s.",
            "firmware": f"Firmware {dev['fw']} is current — no update available.",
            "remove":   f"{dev['id']} scheduled for removal (pending administrator confirmation).",
        }.get(op, "Command sent.")

    alert = f'<div class="alert success">{html.escape(result)}</div>' if result else ""

    reading_rows = "".join(
        f'<tr><td style="color:var(--muted);">{html.escape(k)}</td><td>{html.escape(str(v))}</td></tr>'
        for k, v in _device_readings(dev)
    )

    body = f"""
<div class="page-header">
  <div class="eyebrow">Device Detail</div>
  <h1>{dev['name']}</h1>
  <p>{dev['id']} · {_badge(dev['status'])} · uptime {_uptime(dev)}</p>
</div>
{alert}
<div style="display:grid;grid-template-columns:1fr 1fr;gap:18px;">
  <div class="panel">
    <strong>Identity</strong>
    <table style="margin-top:12px;">
      <tr><td style="color:var(--muted);">IP Address</td><td>{dev['ip']}</td></tr>
      <tr><td style="color:var(--muted);">MAC Address</td><td>{dev['mac']}</td></tr>
      <tr><td style="color:var(--muted);">Type</td><td>{dev['type']}</td></tr>
      <tr><td style="color:var(--muted);">Firmware</td><td>{dev['fw']}</td></tr>
      <tr><td style="color:var(--muted);">Uptime</td><td>{_uptime(dev)}</td></tr>
    </table>
    <div style="margin-top:16px;"><strong>Live Telemetry</strong></div>
    <table style="margin-top:10px;">{reading_rows}</table>
  </div>
  <div class="panel">
    <strong>Actions</strong>
    <form method="POST" style="display:grid;gap:10px;margin-top:14px;">
      <button class="secondary" name="op" value="ping">Ping Device</button>
      <button class="secondary" name="op" value="restart">Restart Device</button>
      <button class="secondary" name="op" value="firmware">Check Firmware</button>
      <button class="secondary" style="color:var(--danger);" name="op" value="remove"
        onclick="return confirm('Remove {dev['id']}?')">Remove Device</button>
    </form>
  </div>
</div>"""
    write_log(200, extra={"page": "device_detail", "dev_id": dev_id, "dev_ip": dev["ip"]})
    return hp_resp(_page(dev["name"], body, active="devices"))

@app.route("/admin/users", methods=["GET"])
def admin_users():
    g = require_login()
    if g: return g

    rows = "".join(f"""<tr>
  <td><strong>{u['username']}</strong></td>
  <td style="color:var(--muted);">{u['role']}</td>
  <td style="color:var(--muted);">{u['email']}</td>
  <td style="color:var(--muted);font-size:12px;">{u['last_login']}</td>
  <td><span class="badge {'good' if u['active'] else 'danger'}">
    {'Active' if u['active'] else 'Disabled'}</span></td>
</tr>""" for u in USERS)

    body = f"""
<div class="page-header">
  <div class="eyebrow">Access Control</div>
  <h1>Users</h1>
  <p>Portal accounts and permission roles</p>
</div>
<div class="panel">
  <table><thead><tr>
    <th>Username</th><th>Role</th><th>Email</th><th>Last Login</th><th>Status</th>
  </tr></thead><tbody>{rows}</tbody></table>
</div>"""
    write_log(200, extra={"page": "admin_users"})
    return hp_resp(_page("Users", body, active="users"))

@app.route("/admin/logs", methods=["GET"])
def admin_logs():
    g = require_login()
    if g: return g

    query = request.args.get("q", "").strip()
    inj = _detect_injection(query)
    if inj:
        out = SHELL_OUTPUTS.get(inj, "")
        write_log(200, extra={"page": "admin_logs_injection", "query": query, "inj": inj})
        return hp_resp(f"<pre>{out}</pre>")

    logs = _recent_logs(real_ip())
    if query:
        logs = [l for l in logs if query.lower() in " ".join(l).lower()]

    rows = "".join(f"""<tr>
  <td style="color:var(--muted);font-size:12px;white-space:nowrap;">{l[0]}</td>
  <td>{_level_badge(l[1])}</td>
  <td style="color:var(--muted);">{l[2]}</td>
  <td>{l[3]}</td>
</tr>""" for l in logs)

    no_rows = '<tr><td colspan="4" style="color:var(--muted);">No matching entries.</td></tr>'
    body = f"""
<div class="page-header">
  <div class="eyebrow">Diagnostics</div>
  <h1>System Logs</h1>
  <p>Platform event log — searchable</p>
</div>
<div class="panel">
  <form method="GET" style="margin-bottom:14px;display:flex;gap:10px;">
    <input name="q" placeholder="Filter logs…" value="{html.escape(query)}" style="max-width:320px;"/>
    <button type="submit" class="secondary">Search</button>
  </form>
  <table><thead><tr><th>Timestamp</th><th>Level</th><th>Source</th><th>Message</th></tr></thead>
  <tbody>{rows or no_rows}</tbody></table>
</div>"""
    write_log(200, extra={"page": "admin_logs", "query": query})
    return hp_resp(_page("System Logs", body, active="logs"))

@app.route("/admin/diagnostics", methods=["GET", "POST"])
def admin_diagnostics():
    g = require_login()
    if g: return g

    host = request.form.get("host", "").strip() if request.method == "POST" else ""
    tool = request.form.get("tool", "ping") if request.method == "POST" else "ping"
    output = None

    if request.method == "POST":
        inj = _detect_injection(host)
        write_log(200, extra={"page": "diagnostics", "tool": tool, "host": host, "injection": inj})
        if inj:
            output = SHELL_OUTPUTS.get(inj, "command not found")
        else:
            output = _fake_tool_output(tool, host)

    out_html = f'<div style="margin-top:14px;"><pre>{html.escape(output)}</pre></div>' if output is not None else ""
    sel = lambda t: "selected" if tool == t else ""
    body = f"""
<div class="page-header">
  <div class="eyebrow">System</div>
  <h1>Network Diagnostics</h1>
  <p>Run a connectivity test from the gateway</p>
</div>
<div class="panel" style="max-width:640px;">
  <form method="POST" style="display:grid;grid-template-columns:1fr 160px 120px;gap:10px;align-items:end;">
    <label style="display:grid;gap:5px;color:var(--muted);font-size:12px;font-weight:700;">TARGET HOST / IP
      <input name="host" placeholder="8.8.8.8" value="{html.escape(host)}"/></label>
    <label style="display:grid;gap:5px;color:var(--muted);font-size:12px;font-weight:700;">TOOL
      <select name="tool">
        <option value="ping" {sel('ping')}>ping</option>
        <option value="traceroute" {sel('traceroute')}>traceroute</option>
        <option value="nslookup" {sel('nslookup')}>nslookup</option>
      </select></label>
    <button type="submit" class="primary">Run</button>
  </form>
  {out_html}
</div>"""
    if request.method == "GET":
        write_log(200, extra={"page": "diagnostics_form"})
    return hp_resp(_page("Diagnostics", body, active="diagnostics"))

def _fake_tool_output(tool, host):
    h = host or "example.com"
    if tool == "traceroute":
        return (f"traceroute to {h} (93.184.216.34), 30 hops max, 60 byte packets\n"
                " 1  gateway (10.0.1.1)  0.412 ms  0.388 ms  0.401 ms\n"
                " 2  100.64.0.1  3.107 ms  3.244 ms  3.190 ms\n"
                " 3  72.14.215.85  11.8 ms  12.1 ms  11.6 ms\n"
                f" 4  {h} (93.184.216.34)  29.7 ms  30.2 ms  29.9 ms")
    if tool == "nslookup":
        return (f"Server:\t\t10.0.1.1\nAddress:\t10.0.1.1#53\n\n"
                f"Non-authoritative answer:\nName:\t{h}\nAddress: 93.184.216.34")
    return (f"PING {h} (93.184.216.34) 56(84) bytes of data.\n"
            f"64 bytes from {h}: icmp_seq=1 ttl=56 time=29.8 ms\n"
            f"64 bytes from {h}: icmp_seq=2 ttl=56 time=30.1 ms\n"
            f"64 bytes from {h}: icmp_seq=3 ttl=56 time=29.6 ms\n"
            f"--- {h} ping statistics ---\n"
            "3 packets transmitted, 3 received, 0% packet loss, time 2003ms")

@app.route("/admin/firmware", methods=["GET", "POST"])
def admin_firmware():
    g = require_login()
    if g: return g

    result = None
    if request.method == "POST":
        f = request.files.get("firmware")
        if f and f.filename:
            data = f.read(MAX_BODY_BYTES + 1)
            size = len(data)
            sha = hashlib.sha256(data).hexdigest()
            inj = _detect_injection(f.filename)
            write_log(200, extra={
                "page": "firmware_upload",
                "filename": f.filename,
                "size_bytes": size,
                "sha256": sha,
                "sample_hex": data[:48].hex(),
                "injection": inj,
            })
            result = (f"Image '{html.escape(f.filename)}' received ({size} bytes). "
                      "Signature valid. Update scheduled for next maintenance window.")
        else:
            write_log(200, extra={"page": "firmware_upload", "filename": None})
            result = "No file selected."

    alert = f'<div class="alert success">{result}</div>' if result else ""
    fw_rows = "".join(
        f'<tr><td>{d["id"]}</td><td>{d["name"]}</td><td>{d["type"]}</td>'
        f'<td style="color:var(--muted);">{d["fw"]}</td></tr>'
        for d in DEVICES
    )
    body = f"""
<div class="page-header">
  <div class="eyebrow">Management</div>
  <h1>Firmware</h1>
  <p>Upload and stage device firmware images</p>
</div>
{alert}
<div style="display:grid;grid-template-columns:1fr 1.2fr;gap:18px;align-items:start;">
  <div class="panel">
    <strong>Upload Image</strong>
    <form method="POST" enctype="multipart/form-data" style="display:grid;gap:12px;margin-top:14px;">
      <input type="file" name="firmware"/>
      <button type="submit" class="primary">Upload &amp; Validate</button>
    </form>
    <p style="color:var(--muted);font-size:12px;margin-top:12px;">
      Accepted: signed .bin / .img (max 2 MB). Images are validated before staging.</p>
  </div>
  <div class="panel">
    <strong>Installed Firmware</strong>
    <table style="margin-top:12px;"><thead><tr><th>ID</th><th>Device</th><th>Type</th><th>Version</th></tr></thead>
    <tbody>{fw_rows}</tbody></table>
  </div>
</div>"""
    return hp_resp(_page("Firmware", body, active="firmware"))

@app.route("/admin/network", methods=["GET", "POST"])
def admin_network():
    g = require_login()
    if g: return g
    saved = request.method == "POST"
    if saved:
        write_log(200, extra={"page": "admin_network_save", "form": dict(request.form)})
    alert = '<div class="alert success">Network settings saved.</div>' if saved else ""
    body = f"""
<div class="page-header">
  <div class="eyebrow">Network</div>
  <h1>Network Configuration</h1>
  <p>Gateway network settings</p>
</div>
{alert}
<div class="panel" style="max-width:600px;">
  <form method="POST">
    <div style="display:grid;gap:14px;">
      <label style="display:grid;gap:5px;color:var(--muted);font-size:12px;font-weight:700;">GATEWAY IP
        <input name="gateway_ip" value="10.0.1.1"/></label>
      <label style="display:grid;gap:5px;color:var(--muted);font-size:12px;font-weight:700;">SUBNET MASK
        <input name="subnet" value="255.255.255.0"/></label>
      <label style="display:grid;gap:5px;color:var(--muted);font-size:12px;font-weight:700;">DNS PRIMARY
        <input name="dns1" value="8.8.8.8"/></label>
      <label style="display:grid;gap:5px;color:var(--muted);font-size:12px;font-weight:700;">DNS SECONDARY
        <input name="dns2" value="8.8.4.4"/></label>
      <label style="display:grid;gap:5px;color:var(--muted);font-size:12px;font-weight:700;">NTP SERVER
        <input name="ntp" value="pool.ntp.org"/></label>
      <div style="display:flex;gap:10px;margin-top:6px;">
        <button type="submit" class="primary">Save Changes</button>
        <button type="reset" class="secondary">Reset</button>
      </div>
    </div>
  </form>
</div>"""
    if not saved:
        write_log(200, extra={"page": "admin_network"})
    return hp_resp(_page("Network", body, active="network"))

@app.route("/admin/config", methods=["GET", "POST"])
def admin_config():
    g = require_login()
    if g: return g
    saved = request.method == "POST"
    if saved:
        form_data = dict(request.form)
        inj = _detect_injection(str(form_data))
        write_log(200, extra={"page": "admin_config_save", "form": form_data, "injection": inj})
        if inj:
            return hp_resp(f"<pre>{SHELL_OUTPUTS.get(inj, '')}</pre>")
    alert = '<div class="alert success">Configuration updated.</div>' if saved else ""
    body = f"""
<div class="page-header">
  <div class="eyebrow">System</div>
  <h1>Settings</h1>
  <p>Platform configuration</p>
</div>
{alert}
<div class="panel" style="max-width:640px;">
  <form method="POST">
    <div style="display:grid;gap:14px;">
      <label style="display:grid;gap:5px;color:var(--muted);font-size:12px;font-weight:700;">SYSTEM NAME
        <input name="system_name" value="DeviceHub-Gateway-01"/></label>
      <label style="display:grid;gap:5px;color:var(--muted);font-size:12px;font-weight:700;">MQTT BROKER HOST
        <input name="mqtt_host" value="10.0.1.30"/></label>
      <label style="display:grid;gap:5px;color:var(--muted);font-size:12px;font-weight:700;">MQTT PORT
        <input name="mqtt_port" value="1883"/></label>
      <label style="display:grid;gap:5px;color:var(--muted);font-size:12px;font-weight:700;">LOG RETENTION (DAYS)
        <input name="log_days" value="30" type="number"/></label>
      <label style="display:grid;gap:5px;color:var(--muted);font-size:12px;font-weight:700;">ADMIN EMAIL
        <input name="admin_email" value="admin@internal.local" type="email"/></label>
      <div style="display:flex;gap:10px;margin-top:6px;">
        <button type="submit" class="primary">Save Configuration</button>
        <button type="reset" class="secondary">Reset</button>
      </div>
    </div>
  </form>
</div>"""
    if not saved:
        write_log(200, extra={"page": "admin_config"})
    return hp_resp(_page("Settings", body, active="config"))

# ── Attack-path bait routes ───────────────────────────────────────────────────

@app.route("/.env")
def fake_env():
    write_log(200, extra={"page": "dot_env_exposure"})
    return hp_resp(FAKE_ENV, 200, "text/plain; charset=utf-8")

@app.route("/.git/config")
def fake_git_config():
    write_log(200, extra={"page": "git_config_exposure"})
    return hp_resp(FAKE_GIT_CONFIG, 200, "text/plain; charset=utf-8")

@app.route("/robots.txt")
def robots():
    write_log(200, extra={"page": "robots_txt"})
    return hp_resp(FAKE_ROBOTS, 200, "text/plain; charset=utf-8")

@app.route("/config.php")
def fake_config_php():
    write_log(200, extra={"page": "config_php_exposure"})
    return hp_resp(FAKE_CONFIG_PHP, 200, "text/plain; charset=utf-8")

@app.route("/wp-login.php", methods=["GET", "POST"])
@app.route("/wp-admin/", methods=["GET", "POST"])
@app.route("/wp-admin", methods=["GET", "POST"])
def wp_admin():
    err = ""
    if request.method == "POST":
        write_log(401, extra={"page": "wp_login_attempt",
                               "username": request.form.get("log", ""),
                               "password": request.form.get("pwd", "")})
        err = '<div style="background:#ffebe8;border:1px solid #f66;padding:8px 12px;border-radius:4px;margin-bottom:14px;font-size:13px;color:#d00;">Error: Incorrect username or password.</div>'
    else:
        write_log(200, extra={"page": "wp_login_form"})

    html_page = f"""<!doctype html><html><head><title>Log In — WordPress</title>
<style>body{{font-family:-apple-system,sans-serif;background:#1d2327;margin:0;display:flex;
align-items:center;justify-content:center;min-height:100vh;}}
.box{{background:#fff;padding:26px;border-radius:4px;width:320px;box-shadow:0 1px 3px rgba(0,0,0,.3);}}
h1{{text-align:center;color:#aaa;font-size:20px;margin-bottom:18px;}}
input{{width:100%;padding:8px;border:1px solid #ddd;border-radius:4px;margin-bottom:12px;
box-sizing:border-box;font-size:13px;}}
label{{font-size:13px;color:#3c4146;display:block;margin-bottom:4px;}}
button{{width:100%;padding:9px;background:#2271b1;color:#fff;border:0;border-radius:4px;
font-size:13px;cursor:pointer;}}
</style></head><body><div class="box">
<h1>WordPress</h1>{err}
<form method="POST">
  <label>Username or Email Address</label><input name="log"/>
  <label>Password</label><input type="password" name="pwd"/>
  <button type="submit">Log In</button>
</form>
</div></body></html>"""
    return hp_resp(html_page)

@app.route("/phpmyadmin/", methods=["GET", "POST"])
@app.route("/phpmyadmin", methods=["GET", "POST"])
@app.route("/pma/", methods=["GET", "POST"])
@app.route("/pma", methods=["GET", "POST"])
def phpmyadmin():
    err = ""
    if request.method == "POST":
        write_log(401, extra={"page": "phpmyadmin_attempt",
                               "username": request.form.get("pma_username", ""),
                               "password": request.form.get("pma_password", "")})
        err = '<p style="color:red;font-size:13px;">Access denied for this user.</p>'
    else:
        write_log(200, extra={"page": "phpmyadmin_form"})
    html_page = f"""<!doctype html><html><head><title>phpMyAdmin</title>
<style>body{{font-family:sans-serif;background:#f8f8f8;margin:0;display:flex;
align-items:center;justify-content:center;min-height:100vh;}}
.box{{background:#fff;padding:28px;border-radius:8px;width:300px;
box-shadow:0 2px 10px rgba(0,0,0,.15);}}
input{{width:100%;padding:8px;border:1px solid #ccc;border-radius:4px;margin-bottom:12px;
box-sizing:border-box;font-size:13px;}}
label{{font-size:12px;color:#666;display:block;margin-bottom:4px;}}
button{{width:100%;padding:9px;background:#4a4a77;color:#fff;border:0;border-radius:4px;
font-size:13px;cursor:pointer;}}
h2{{color:#4a4a77;margin:0 0 18px;font-size:18px;}}
</style></head><body><div class="box"><h2>phpMyAdmin</h2>{err}
<form method="POST">
  <label>Username</label><input name="pma_username" value="root"/>
  <label>Password</label><input type="password" name="pma_password"/>
  <button type="submit">Go</button>
</form></div></body></html>"""
    return hp_resp(html_page)

# ── Fake JSON API ─────────────────────────────────────────────────────────────

@app.route("/api/v1/devices", methods=["GET"])
def api_devices():
    write_log(200, extra={"page": "api_devices"})
    data = [{"id": d["id"], "name": d["name"], "ip": d["ip"],
              "status": d["status"], "uptime": _uptime(d), "fw": d["fw"]} for d in DEVICES]
    return hp_resp(json.dumps({"devices": data, "count": len(data)}, indent=2),
                   200, "application/json; charset=utf-8")

@app.route("/api/v1/users", methods=["GET"])
def api_users():
    write_log(200, extra={"page": "api_users"})
    data = [{"id": u["id"], "username": u["username"],
              "role": u["role"], "active": u["active"]} for u in USERS]
    return hp_resp(json.dumps({"users": data}, indent=2),
                   200, "application/json; charset=utf-8")

@app.route("/api/v1/status", methods=["GET"])
def api_status():
    write_log(200, extra={"page": "api_status"})
    return hp_resp(json.dumps({
        "system": "DeviceHub Pro", "version": "3.4.1",
        "uptime": _uptime(DEVICES[0]),
        "devices_online": sum(1 for d in DEVICES if d["status"] == "online"),
        "devices_total": len(DEVICES),
        "mqtt_broker": "10.0.1.30:1883",
        "timestamp": utc_now(),
    }, indent=2), 200, "application/json; charset=utf-8")

@app.route("/health", methods=["GET", "HEAD"])
def health():
    write_log(200, extra={"page": "health"})
    return hp_resp('{"status":"ok"}', 200, "application/json; charset=utf-8")

# ── Catch-all ─────────────────────────────────────────────────────────────────

@app.route("/", defaults={"path": ""}, methods=["POST","PUT","PATCH","DELETE","OPTIONS"])
@app.route("/<path:path>", methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"])
def catch_all(path):
    full = clipped_body() + request.query_string.decode("utf-8", errors="ignore")
    inj  = _detect_injection(full)
    if inj:
        write_log(200, extra={"catch_all": True, "path": path, "injection": inj})
        return hp_resp(f"<pre>{SHELL_OUTPUTS.get(inj, 'command not found')}</pre>")
    status = 404 if request.method in {"GET", "HEAD"} else 200
    write_log(status, extra={"catch_all": True, "path": path})
    if "json" in request.headers.get("Accept", ""):
        return hp_resp('{"error":"not found"}', 404, "application/json; charset=utf-8")
    return hp_resp("Not Found" if status == 404 else "OK", status, "text/plain; charset=utf-8")

# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host=os.environ.get("LISTEN_HOST", "0.0.0.0"),
            port=int(os.environ.get("PORT", "8080")))
