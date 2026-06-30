FROM python:3.10-slim

WORKDIR /app

# The proxies import rules/state_cache from the router package,
# so we copy both the proxy scripts and the router modules together.
COPY proxy/http_decision_proxy.py  ./
COPY proxy/mqtt_decision_proxy.py  ./
COPY proxy/real_http_backend.py    ./
COPY router/rules.py               ./
COPY router/session_router.py      ./
COPY router/state_cache.py         ./
COPY router/mqtt_wire.py           ./

ENV PYTHONUNBUFFERED=1

# Default target; override with --entrypoint at runtime
CMD ["python", "http_decision_proxy.py", "--listen-host", "0.0.0.0", "--listen-port", "80"]
