# /opt/iot-honeypot/router/state_cache.py
# ============================================================
# state_cache.py
# Simple persistent IP state storage for routing decisions
# ============================================================

import json
import os
import tempfile
import threading
from datetime import datetime, timedelta, timezone


STATE_FILE = "/opt/iot-honeypot/router/state_cache.json"
DEFAULT_SESSION_TTL_SECONDS = int(os.environ.get("ROUTER_SESSION_TTL_SECONDS", "1800"))


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def parse_utc_timestamp(value):
    text = str(value or "").strip()
    if not text:
        return None

    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"

    try:
        return datetime.fromisoformat(text)
    except Exception:
        return None


class StateCache:
    def __init__(self, state_file=STATE_FILE, session_ttl_seconds=DEFAULT_SESSION_TTL_SECONDS):
        self.state_file = state_file
        self.session_ttl_seconds = max(int(session_ttl_seconds or DEFAULT_SESSION_TTL_SECONDS), 1)
        self._lock = threading.RLock()
        self.state = {}
        self.load()

    def load(self):
        with self._lock:
            if not os.path.exists(self.state_file):
                self.state = {"ips": {}, "sessions": {}, "meta": {}}
                return

            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    self.state = json.load(f)
                    self._normalize_state()
            except Exception:
                self.state = {"ips": {}, "sessions": {}, "meta": {}}

            self._expire_sessions()
            self._expire_ip_timeouts()

    def _normalize_state(self):
        raw_state = self.state if isinstance(self.state, dict) else {}
        ips = raw_state.get("ips") if isinstance(raw_state.get("ips"), dict) else {}
        sessions = raw_state.get("sessions") if isinstance(raw_state.get("sessions"), dict) else {}
        meta = raw_state.get("meta") if isinstance(raw_state.get("meta"), dict) else {}

        # Migrate the older flat IP-only state format into the namespaced layout.
        for key, value in raw_state.items():
            if key in {"ips", "sessions", "meta"}:
                continue
            if isinstance(value, dict):
                ips.setdefault(key, value)

        self.state = {
            "ips": ips,
            "sessions": sessions,
            "meta": meta,
        }

    def _ip_bucket(self):
        self._normalize_state()
        return self.state.setdefault("ips", {})

    def _session_bucket(self):
        self._normalize_state()
        return self.state.setdefault("sessions", {})

    def _expire_sessions(self):
        sessions = self._session_bucket()
        now = datetime.now(timezone.utc)

        for session_id, entry in list(sessions.items()):
            last_seen = parse_utc_timestamp(entry.get("last_seen_utc"))
            if last_seen is None:
                del sessions[session_id]
                continue

            age_seconds = (now - last_seen).total_seconds()
            if age_seconds > self.session_ttl_seconds:
                del sessions[session_id]

    def _expire_ip_timeouts(self):
        ips = self._ip_bucket()
        now = datetime.now(timezone.utc)

        for source_ip, entry in list(ips.items()):
            timeout_until = parse_utc_timestamp(entry.get("http_timeout_until_utc"))
            if timeout_until is not None and timeout_until <= now:
                for key in (
                    "http_flagged",
                    "http_suspicious",
                    "http_last_reason",
                    "http_last_seen_utc",
                    "http_timeout_until_utc",
                ):
                    entry.pop(key, None)

            generic_timeout_until = parse_utc_timestamp(entry.get("flagged_until_utc"))
            if generic_timeout_until is None:
                last_seen = parse_utc_timestamp(entry.get("last_seen_utc"))
                if last_seen is not None:
                    generic_timeout_until = last_seen + timedelta(seconds=self.session_ttl_seconds)

            if generic_timeout_until is not None and generic_timeout_until <= now:
                for key in (
                    "flagged",
                    "suspicious",
                    "last_reason",
                    "last_seen_utc",
                    "flagged_until_utc",
                    "suspicious_until_utc",
                    "suspicious_count",
                    "flagged_count",
                ):
                    entry.pop(key, None)

    def save(self):
        with self._lock:
            self._normalize_state()
            self._expire_sessions()
            self._expire_ip_timeouts()
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)

            fd, temp_path = tempfile.mkstemp(
                prefix="state_cache_",
                suffix=".json",
                dir=os.path.dirname(self.state_file)
            )

            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(self.state, f, indent=2)
                os.replace(temp_path, self.state_file)
            finally:
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except Exception:
                        pass

    def get_ip_state(self, source_ip):
        with self._lock:
            self._expire_ip_timeouts()
            return dict(self._ip_bucket().get(source_ip, {}))

    def is_flagged(self, source_ip):
        with self._lock:
            return self._ip_bucket().get(source_ip, {}).get("flagged", False)

    def mark_suspicious(self, source_ip, reason, protocol=None):
        with self._lock:
            entry = self._ip_bucket().setdefault(source_ip, {})
            entry["suspicious"] = True
            entry["last_reason"] = reason
            entry["last_seen_utc"] = utc_now()
            entry["suspicious_until_utc"] = (
                datetime.now(timezone.utc) + timedelta(seconds=self.session_ttl_seconds)
            ).isoformat()

            if protocol:
                entry["last_protocol"] = protocol

            entry["suspicious_count"] = entry.get("suspicious_count", 0) + 1
            self.save()

    def mark_flagged(self, source_ip, reason, protocol=None, attack_type=None):
        with self._lock:
            entry = self._ip_bucket().setdefault(source_ip, {})
            entry["flagged"] = True
            entry["suspicious"] = True
            entry["last_reason"] = reason
            entry["last_seen_utc"] = utc_now()
            entry["flagged_until_utc"] = (
                datetime.now(timezone.utc) + timedelta(seconds=self.session_ttl_seconds)
            ).isoformat()
            entry["suspicious_until_utc"] = entry["flagged_until_utc"]

            if protocol:
                entry["last_protocol"] = protocol

            if attack_type:
                entry["last_attack_type"] = attack_type

            entry["flagged_count"] = entry.get("flagged_count", 0) + 1
            self.save()

    def mark_route(self, source_ip, route, reason, protocol=None):
        with self._lock:
            entry = self._ip_bucket().setdefault(source_ip, {})
            entry["last_route"] = route
            entry["last_reason"] = reason
            entry["last_seen_utc"] = utc_now()

            if protocol:
                entry["last_protocol"] = protocol

            entry["route_count"] = entry.get("route_count", 0) + 1
            self.save()

    def get_session_state(self, session_id):
        if not session_id:
            return {}
        with self._lock:
            self._expire_sessions()
            return dict(self._session_bucket().get(session_id, {}))

    def mark_session_suspicious(self, session_id, reason, protocol=None, source_ip=None):
        if not session_id:
            return

        with self._lock:
            entry = self._session_bucket().setdefault(session_id, {})
            entry.setdefault("created_utc", utc_now())
            entry["suspicious"] = True
            entry["last_reason"] = reason
            entry["last_seen_utc"] = utc_now()

            if protocol:
                entry["last_protocol"] = protocol

            if source_ip:
                entry["source_ip"] = source_ip

            entry["suspicious_count"] = entry.get("suspicious_count", 0) + 1
            self.save()

    def mark_session_flagged(self, session_id, reason, protocol=None, attack_type=None, source_ip=None):
        if not session_id:
            return

        with self._lock:
            entry = self._session_bucket().setdefault(session_id, {})
            entry.setdefault("created_utc", utc_now())
            entry["flagged"] = True
            entry["suspicious"] = True
            entry["last_reason"] = reason
            entry["last_seen_utc"] = utc_now()

            if protocol:
                entry["last_protocol"] = protocol

            if attack_type:
                entry["last_attack_type"] = attack_type

            if source_ip:
                entry["source_ip"] = source_ip

            entry["flagged_count"] = entry.get("flagged_count", 0) + 1
            self.save()

    def mark_session_route(self, session_id, route, reason, protocol=None, source_ip=None):
        if not session_id:
            return

        with self._lock:
            entry = self._session_bucket().setdefault(session_id, {})
            entry.setdefault("created_utc", utc_now())
            entry["last_route"] = route
            entry["last_reason"] = reason
            entry["last_seen_utc"] = utc_now()

            if protocol:
                entry["last_protocol"] = protocol

            if source_ip:
                entry["source_ip"] = source_ip

            entry["route_count"] = entry.get("route_count", 0) + 1
            self.save()

    def mark_http_source_timeout(self, source_ip, reason):
        if not source_ip:
            return

        with self._lock:
            now = datetime.now(timezone.utc)
            entry = self._ip_bucket().setdefault(source_ip, {})
            entry["http_flagged"] = True
            entry["http_suspicious"] = True
            entry["http_last_reason"] = reason
            entry["http_last_seen_utc"] = now.isoformat()
            entry["http_timeout_until_utc"] = (
                now + timedelta(seconds=self.session_ttl_seconds)
            ).isoformat()
            entry["last_protocol"] = "http"
            entry["http_timeout_count"] = entry.get("http_timeout_count", 0) + 1
            self.save()

    def clear_ip(self, source_ip):
        with self._lock:
            ips = self._ip_bucket()
            if source_ip in ips:
                del ips[source_ip]
                self.save()

    def clear_session(self, session_id):
        with self._lock:
            sessions = self._session_bucket()
            if session_id in sessions:
                del sessions[session_id]
                self.save()

    def clear_all(self):
        with self._lock:
            self.state = {"ips": {}, "sessions": {}, "meta": {}}
            self.save()
