#!/usr/bin/env python3
"""
HTTP honeypot readiness check.

This validates the honeypot app behavior before a real public test on port 8080:
request handling, credential capture, response_status logging, and source IP cleanup.
"""

import argparse
import importlib
import json
import os
import sys
import tempfile
from pathlib import Path


def read_jsonl(path):
    rows = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def assert_true(condition, message):
    if not condition:
        raise AssertionError(message)


def run_app_check(log_path):
    os.environ["LOG_PATH"] = str(log_path)
    if "app" in sys.modules:
        del sys.modules["app"]

    app_module = importlib.import_module("app")
    client = app_module.app.test_client()

    checks = []

    response = client.get("/health", headers={"X-Forwarded-For": "203.0.113.10, 127.0.0.1"})
    checks.append(("health_200", response.status_code == 200))

    response = client.get("/admin", headers={"User-Agent": "curl/8.0", "X-Forwarded-For": "203.0.113.11, 127.0.0.1"})
    checks.append(("admin_fake_login_200", response.status_code == 200 and b"Web Management Login" in response.data))

    response = client.post(
        "/login",
        data={"username": "root", "password": "toor"},
        headers={"X-Forwarded-For": "203.0.113.12, 127.0.0.1"},
    )
    checks.append(("bad_login_401", response.status_code == 401))

    response = client.post(
        "/login",
        data={"username": "admin", "password": "1234"},
        headers={"X-Forwarded-For": "203.0.113.13, 127.0.0.1"},
    )
    checks.append(("fake_success_200", response.status_code == 200 and b"Admin Control Panel" in response.data))

    response = client.get("/.env", headers={"X-Forwarded-For": "203.0.113.14, 127.0.0.1"})
    checks.append(("unknown_path_404", response.status_code == 404))

    rows = read_jsonl(log_path)
    checks.append(("five_logs_written", len(rows) == 5))
    checks.append(("response_status_logged", all("response_status" in row for row in rows)))
    checks.append(("forwarded_ip_cleaned", all("," not in str(row.get("ip", "")) for row in rows)))
    checks.append(("credentials_logged", any((row.get("extra") or {}).get("username") == "root" for row in rows)))
    checks.append(("fake_success_logged", any((row.get("extra") or {}).get("fake_success") is True for row in rows)))

    for name, passed in checks:
        assert_true(passed, f"failed: {name}")

    return {
        "log_path": str(log_path),
        "checks": {name: passed for name, passed in checks},
        "sample_logs": rows,
    }


def parse_args():
    parser = argparse.ArgumentParser(description="Run HTTP honeypot readiness checks")
    parser.add_argument(
        "--log-path",
        default="",
        help="Optional JSONL log path. Defaults to a temporary file.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if args.log_path:
        log_path = Path(args.log_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        if log_path.exists():
            log_path.unlink()
    else:
        fd, temp_path = tempfile.mkstemp(prefix="hb_ready_check_", suffix=".jsonl")
        os.close(fd)
        log_path = Path(temp_path)

    result = run_app_check(log_path)

    print("HTTP honeypot readiness: PASS")
    for name, passed in result["checks"].items():
        print(f"- {name}: {'PASS' if passed else 'FAIL'}")
    print(f"log_path: {result['log_path']}")
    print("sample:")
    for row in result["sample_logs"]:
        print(json.dumps(row, ensure_ascii=False))


if __name__ == "__main__":
    main()
