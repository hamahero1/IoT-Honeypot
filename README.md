# IoT Honeypot System — Deployment Guide

A multi-protocol honeypot that captures, classifies, and visualises IoT attack traffic in real time.  
Protocols: **HTTP · MQTT · RTSP · SSH**  
Dashboard: **http://YOUR-IP:8502** (SOC prototype) | API: **http://YOUR-IP:8501**

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Port Map](#2-port-map)
3. [What Lives in `codes/`](#3-what-lives-in-codes)
4. [Install Docker](#4-install-docker)
5. [Open the Ports — AWS Security Group + Firewall](#5-open-the-ports--aws-security-group--firewall)
6. [Option A — Dashboard Only (Docker Compose)](#6-option-a--dashboard-only-docker-compose)
7. [Option B — Full System (Docker Compose)](#7-option-b--full-system-docker-compose)
8. [Option C — Manual Setup with systemd](#8-option-c--manual-setup-with-systemd)
9. [ML Models — Where They Come From](#9-ml-models--where-they-come-from)
10. [Integrating on a New Machine](#10-integrating-on-a-new-machine)
11. [Health Check](#11-health-check)
12. [Environment Variables Reference](#12-environment-variables-reference)

---

## 1. Architecture Overview

```
Internet traffic → ports 80 / 1883 / 554 / 22
    │
    ├─ HTTP 80  → http_decision_proxy.py ──► real backend :28080   (safe traffic)
    │                                    └─► http honeypot :8080   (attackers)
    │
    ├─ MQTT 1883 → mqtt_decision_proxy.py ─► real broker :11883    (safe clients)
    │                                    └─► honeypot log bucket   (attackers)
    │
    ├─ RTSP 554 → MediaMTX container ──────► rtsp_log_router.py   (log-bridge)
    │
    └─ SSH  22  → Cowrie honeypot ─────────► ssh_log_router.py    (log-bridge)
                          │
                          ▼
          logs/routing_decisions.jsonl  +  per-protocol JSONL files
                          │
                rebuild_unified_events.py
                          │
                          ▼
              normalized/unified_events.jsonl
                          │
                 ml-engine/predictor.py
             (feature extraction → sklearn model → rule classifier)
                          │
                          ▼
              ml-engine/output/predictions.jsonl
                          │
              ┌───────────┴────────────┐
     FastAPI (8501)            nginx (8502)
     /api/summary              soc-dashboard-prototype.html
     /api/events               (the main UI you see)
     /ws/events (WebSocket)
```

**Inline proxies** (HTTP, MQTT): the proxy sees every packet first and decides real vs honeypot.  
**Log-bridge** (RTSP, SSH): the service handles the connection; the log router reads its logs.

---

## 2. Port Map

| Port  | Service                          | Protocol |
|-------|----------------------------------|----------|
| 80    | HTTP decision proxy (public)     | TCP      |
| 1883  | MQTT decision proxy (public)     | TCP      |
| 554   | RTSP (MediaMTX, log-bridge)      | TCP/UDP  |
| 22    | SSH (Cowrie, log-bridge)         | TCP      |
| 8080  | HTTP honeypot (Flask)            | TCP      |
| 8501  | Dashboard API (FastAPI)          | TCP      |
| **8502**  | **SOC Dashboard (main UI)**  | TCP      |
| 11883 | Real MQTT broker (Mosquitto)     | TCP      |
| 28080 | Real HTTP backend (Flask)        | TCP      |

---

## 3. What Lives in `codes/`

```
codes/
├── proxy/                  ← the "sub-proxy" decision layer
│   ├── http_decision_proxy.py   port 80  → real :28080 or honeypot :8080
│   ├── mqtt_decision_proxy.py   port 1883 → real broker or honeypot
│   ├── real_http_backend.py     the safe backend served on :28080
│   └── Dockerfile
├── http-honeypot/          ← fake IoT device web UI served on :8080
│   ├── app.py                   Flask fake-device portal (login pages, CGI traps)
│   ├── hb_ready_check.py
│   └── Dockerfile
├── router/                 routing brain + log-bridge routers
│   ├── rules.py                 scoring rules (score ≥ 3 → honeypot)
│   ├── session_router.py · state_cache.py
│   ├── rtsp_log_router.py · ssh_log_router.py   (RTSP/SSH log-bridge)
│   └── mqtt_router_sniffer.py · mqtt_wire.py · normalize_http_router.py
├── normalization/          rebuild_unified_events.py + per-protocol normalizers
├── ml-engine/              ← the ML engine
│   ├── predictor.py · feature_extractor.py · config.json · Dockerfile
│   └── models/                  trained .pkl files (model, scaler, encoder, columns)
├── dashboard-api/          ← dashboard backend (FastAPI on :8501)
│   ├── app.py · requirements.txt · Dockerfile
├── dashboard-ui/           ← dashboard front-ends (all UIs)
│   ├── soc-dashboard-prototype.html   main SOC UI on :8502
│   ├── index.html · src/main.jsx · src/styles.css   React app (served by :8501)
│   ├── nginx.conf · package.json · Dockerfile
├── mqtt/                   mosquitto.conf · sniffer/sniff.py · deploy scripts
├── config/                 cowrie config, blocked/excluded IP lists
├── systemd/                systemd unit files for every service
├── scripts/                check_health.sh · run_dashboard.sh · run_pipeline_*.sh
├── docker-compose.yml          ← FULL system (all services)
└── docker-compose.dashboard.yml ← dashboard only (8501 + 8502)
```

> **The web faces in here:** `http-honeypot/app.py` (fake device on **:8080**),
> `proxy/real_http_backend.py` (the real safe site on **:28080**),
> `dashboard-ui/soc-dashboard-prototype.html` (the SOC dashboard you actually use, on **:8502**),
> which reads its data from the FastAPI JSON API on **:8501** (`dashboard-api/app.py`).
> The React sources under `dashboard-ui/src/` are the original build source for an
> alternative dashboard and are included for completeness — the Docker setup serves
> the prototype HTML, so building React is optional.

> **Not bundled here (third-party services):** the **SSH** honeypot (Cowrie) and the
> **RTSP** server (MediaMTX) run as their own services and feed the pipeline through
> their log files (log-bridge mode). The Docker Compose stack covers HTTP, MQTT, the
> pipeline, the ML engine and the dashboards. To capture SSH/RTSP too, install Cowrie
> and MediaMTX on the host — see [Section 8](#8-option-c--manual-setup-with-systemd).

---

## 4. Install Docker

### Ubuntu / Debian

```bash
# Remove old versions
sudo apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true

# Install prerequisites
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release

# Add Docker's official GPG key
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Add the repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine + Compose plugin
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Allow running Docker without sudo (log out and back in after this)
sudo usermod -aG docker $USER

# Verify
docker --version
docker compose version
```

### macOS

```bash
# Install Docker Desktop from https://www.docker.com/products/docker-desktop/
# OR via Homebrew:
brew install --cask docker
```

### Windows

Download and install **Docker Desktop** from https://www.docker.com/products/docker-desktop/  
Enable WSL 2 backend during installation.

---

## 5. Open the Ports — AWS Security Group + Firewall

For traffic to reach the honeypot from the internet, a port must be open in **two**
places: the **AWS Security Group** (the cloud-level firewall on your EC2 instance)
**and** the **host firewall** (UFW) on the server itself. If a port "is not open",
it is almost always the AWS Security Group — open it there first.

### Ports you need to open

| Port  | Protocol | Why                                   | Source         |
|-------|----------|---------------------------------------|----------------|
| 22    | TCP      | SSH honeypot (Cowrie) / your admin SSH| Your IP / Any  |
| 80    | TCP      | HTTP decision proxy (public)          | Anywhere (0.0.0.0/0) |
| 554   | TCP      | RTSP (MediaMTX)                       | Anywhere       |
| 1883  | TCP      | MQTT decision proxy (public)          | Anywhere       |
| 8501  | TCP      | Dashboard API (FastAPI)               | Your IP        |
| 8502  | TCP      | SOC Dashboard (main UI)               | Your IP        |

> Keep the **dashboard** ports (8501/8502) restricted to **your own IP** — they are
> for the operator, not the public. The **honeypot** ports (80, 1883, 554, 22) are
> open to the world on purpose: that is the bait.

### A. Open the ports in AWS (Security Group inbound rules)

If a port is closed from the outside, **go to AWS and open it in the Security Group**:

1. Sign in to the **AWS Console** → **EC2** → **Instances**.
2. Click your honeypot instance → **Security** tab → click its **Security group**
   (e.g. `launch-wizard-1` / `sg-xxxxxxxx`).
3. Click **Edit inbound rules** → **Add rule** (add one row per port).
4. For each port set:
   - **Type:** `Custom TCP`  (for SSH you can pick the `SSH` type)
   - **Port range:** the port number (e.g. `8502`)
   - **Source:** `Anywhere-IPv4` `0.0.0.0/0` for the public honeypot ports,
     or `My IP` for the dashboard/admin ports
   - **Description:** e.g. `SOC dashboard`, `HTTP honeypot`
5. Click **Save rules**. Changes apply immediately — no instance restart needed.

A finished inbound-rule set looks like this:

```
Type         Protocol  Port range  Source        Description
SSH          TCP       22          My IP         admin SSH
Custom TCP   TCP       80          0.0.0.0/0     HTTP honeypot
Custom TCP   TCP       554         0.0.0.0/0     RTSP honeypot
Custom TCP   TCP       1883        0.0.0.0/0     MQTT honeypot
Custom TCP   TCP       8501        My IP         Dashboard API
Custom TCP   TCP       8502        My IP         SOC dashboard
```

> Tip: you can do the same from the CLI once you know the group id:
> ```bash
> aws ec2 authorize-security-group-ingress \
>   --group-id sg-xxxxxxxx --protocol tcp --port 8502 --cidr YOUR.IP.ADDR.0/32
> ```

### B. Open the ports in the host firewall (UFW)

After the Security Group, allow the same ports on the server itself:

```bash
sudo ufw allow 22/tcp      # SSH (keep this BEFORE enabling UFW or you lock yourself out)
sudo ufw allow 80/tcp      # HTTP honeypot
sudo ufw allow 554/tcp     # RTSP
sudo ufw allow 1883/tcp    # MQTT
sudo ufw allow 8501/tcp    # Dashboard API
sudo ufw allow 8502/tcp    # SOC dashboard
sudo ufw enable
sudo ufw status numbered   # verify
```

### C. Verify a port is reachable

```bash
# On the server — is something listening?
sudo ss -tlnp | grep -E ':(80|1883|554|8501|8502)'

# From your laptop — is it open through AWS + UFW?
nc -zv YOUR-EC2-PUBLIC-IP 8502
curl -sS http://YOUR-EC2-PUBLIC-IP:8501/api/health
```

If `ss` shows the service listening but the laptop test fails, the block is the
**AWS Security Group** — go back to step A.

---

## 6. Option A — Dashboard Only (Docker Compose)

Use this if the honeypot is already running somewhere and you just want to view the dashboard.

### Requirements

- Docker installed
- Three directories (or files) that already contain data:
  - `normalized/unified_events.jsonl`
  - `ml-engine/output/predictions.jsonl`
  - `logs/` (per-protocol JSONL files)

### Steps

```bash
# 1. Clone / copy this repository to the new machine
git clone <your-repo-url> iot-honeypot
cd iot-honeypot/codess

# 2. Point the compose file at your data directories
export UNIFIED_EVENTS_DIR=/path/to/normalized
export PREDICTIONS_DIR=/path/to/ml-engine/output
export LOGS_DIR=/path/to/logs

# 3. Build and start
docker compose -f docker-compose.dashboard.yml up -d --build

# 4. Open the dashboard
#    SOC Dashboard  → http://localhost:8502
#    API docs       → http://localhost:8501/docs
```

### Stop

```bash
docker compose -f docker-compose.dashboard.yml down
```

---

## 7. Option B — Full System (Docker Compose)

Runs every component: proxies, honeypots, pipeline, ML engine, and dashboards.

### Pre-requisites

- Docker installed (see section 4)
- Ports 80, 1883, 8501, 8502 free on the host
- Trained ML model files in `ml-engine/models/` (see section 8)
- For SSH and RTSP: Cowrie and MediaMTX still need to run on the host (log-bridge mode)

### Steps

```bash
# 1. Enter the code directory
cd /opt/iot-honeypot/codes        # or wherever you put the code

# 2. Copy ML model files into the expected location
mkdir -p ../ml-engine/models
cp /path/to/your/models/*.pkl ../ml-engine/models/

# 3. Build all images and start
docker compose up -d --build

# 4. Watch the logs
docker compose logs -f

# 5. Verify everything is running
docker compose ps
```

### Accessing the system

| What | URL |
|------|-----|
| SOC Dashboard (main UI) | http://YOUR-IP:8502 |
| API (FastAPI docs)      | http://YOUR-IP:8501/docs |
| API health              | http://YOUR-IP:8501/api/health |
| API summary             | http://YOUR-IP:8501/api/summary |

### Stop

```bash
docker compose down
```

### Rebuild a single service after a code change

```bash
docker compose up -d --build dashboard-api
```

---

## 8. Option C — Manual Setup with systemd

Use this when you want to run the system natively (no Docker) on a Linux server.

### Prerequisites

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip nodejs npm mosquitto
```

### Step 1 — Clone and set up directories

```bash
sudo mkdir -p /opt/iot-honeypot
sudo chown $USER /opt/iot-honeypot
git clone <your-repo-url> /opt/iot-honeypot
cd /opt/iot-honeypot
mkdir -p logs normalized ml-engine/output router config
```

### Step 2 — Python environments

```bash
# Dashboard API
cd /opt/iot-honeypot/dashboard_api
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
deactivate

# ML engine
cd /opt/iot-honeypot/ml-engine
python3 -m venv venv && source venv/bin/activate
pip install numpy pandas scikit-learn joblib
deactivate
```

### Step 3 — Build React UI (optional — the static HTML at 8502 works without this)

```bash
cd /opt/iot-honeypot/dashboard_ui
npm install
npm run build
cp -a dist/. ../dashboard_api/static/
```

### Step 4 — HTTP Honeypot container

```bash
cd /opt/iot-honeypot/http-honeypot
docker build -t iot-http-honeypot .
docker run -d --name iot-http-honeypot \
  -v /opt/iot-honeypot/logs:/logs \
  -p 8080:8080 \
  --restart always \
  iot-http-honeypot
```

### Step 5 — Set up the SOC dashboard prototype directory

```bash
mkdir -p /opt/iot-honeypot/dashboard_ui_prototype
ln -sf /opt/iot-honeypot/dashboard_ui/soc-dashboard-prototype.html \
       /opt/iot-honeypot/dashboard_ui_prototype/index.html
```

### Step 6 — Install systemd services

```bash
sudo cp /opt/iot-honeypot/codes/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload

# Enable and start each service
sudo systemctl enable --now iot-http-honeypot.service
sudo systemctl enable --now iot-http-real-backend.service
sudo systemctl enable --now iot-http-router-proxy.service
sudo systemctl enable --now iot-mqtt-router-proxy.service
sudo systemctl enable --now iot-pipeline-auto.service
sudo systemctl enable --now iot-predictor.service
sudo systemctl enable --now iot-dashboard.service
sudo systemctl enable --now iot-dashboard-prototype.service
```

### Step 7 — Verify

```bash
sudo systemctl status iot-dashboard-prototype.service --no-pager
curl http://localhost:8501/api/health
```

---

## 9. ML Models — Where They Come From

The predictor requires four trained files in `ml-engine/models/`:

| File                   | Contents                            |
|------------------------|-------------------------------------|
| `iot_honeypot_model.pkl` | Trained sklearn classifier        |
| `label_encoder.pkl`    | LabelEncoder for attack categories  |
| `scaler.pkl`           | StandardScaler for feature matrix   |
| `feature_columns.pkl`  | Ordered list of feature column names|

These were trained on **CIC IoT 2023 + UNSW-NB15** datasets with 5 categories:
`Normal`, `Scanning`, `Brute_Force`, `DDoS`, `Exploit_Attempt`

### To retrain on a new machine

```bash
cd /opt/iot-honeypot/ml-engine
source venv/bin/activate
# Produce features from current log data
python feature_extractor.py
# Train (you need a training script — contact the project author)
# Or copy the .pkl files from the original machine
deactivate
```

If you have the `.pkl` files from the original system, just copy them:

```bash
scp ubuntu@ORIGINAL-IP:/opt/iot-honeypot/ml-engine/models/*.pkl \
    /opt/iot-honeypot/ml-engine/models/
```

---

## 10. Integrating on a New Machine

### Full migration checklist

```
[ ] Install Docker (section 4)
[ ] Copy or clone the code to /opt/iot-honeypot (or any path)
[ ] Copy ml-engine/models/*.pkl from the original machine
[ ] Copy normalized/unified_events.jsonl  (optional — for historical data)
[ ] Copy ml-engine/output/predictions.jsonl  (optional)
[ ] Update paths in code/ml-engine/config.json if you changed the base directory
[ ] Open firewall ports: 80, 1883, 554, 22, 8501, 8502
[ ] Run docker compose up -d --build  (full system)
    OR follow systemd steps for native install
[ ] Verify: curl http://localhost:8501/api/health
[ ] Open http://YOUR-IP:8502 in a browser
```

### config.json path update

If you install to a different base path than `/opt/iot-honeypot`, edit `ml-engine/config.json`:

```json
{
  "log_files": {
    "http": "/YOUR/PATH/logs/http_honeypot.jsonl",
    "ssh":  "/YOUR/PATH/logs/ssh_router_events.jsonl",
    "mqtt": "/YOUR/PATH/logs/mqtt_honeypot.jsonl"
  },
  "model_path":   "/YOUR/PATH/ml-engine/models/iot_honeypot_model.pkl",
  "encoder_path": "/YOUR/PATH/ml-engine/models/label_encoder.pkl",
  "scaler_path":  "/YOUR/PATH/ml-engine/models/scaler.pkl",
  "columns_path": "/YOUR/PATH/ml-engine/models/feature_columns.pkl",
  "output_path":  "/YOUR/PATH/ml-engine/output/predictions.jsonl",
  "run_every_seconds": 60
}
```

### Firewall (UFW)

```bash
sudo ufw allow 80/tcp
sudo ufw allow 1883/tcp
sudo ufw allow 22/tcp
sudo ufw allow 554/tcp
sudo ufw allow 8501/tcp
sudo ufw allow 8502/tcp
sudo ufw enable
```

---

## 11. Health Check

```bash
# Quick status of all containers
docker compose ps

# Check the dashboard API is responding
curl -sS http://localhost:8501/api/health | python3 -m json.tool

# Count live events
wc -l /opt/iot-honeypot/normalized/unified_events.jsonl
wc -l /opt/iot-honeypot/ml-engine/output/predictions.jsonl

# Full health script (shows memory, disk, attack distribution)
bash /opt/iot-honeypot/codes/scripts/check_health.sh

# Stream live logs
tail -n 0 -F \
  /opt/iot-honeypot/logs/routing_decisions.jsonl \
  /opt/iot-honeypot/normalized/unified_events.jsonl \
  /opt/iot-honeypot/ml-engine/output/predictions.jsonl
```

---

## 12. Environment Variables Reference

| Variable | Default | Where used |
|----------|---------|------------|
| `DASHBOARD_MAX_EVENTS` | 8000 | dashboard-api — max events loaded into memory |
| `DASHBOARD_MAX_ROUTES` | 8000 | dashboard-api — max routing decisions loaded |
| `DASHBOARD_WINDOW_PACKETS` | 2500 | dashboard-api — packet-drawer window size |
| `DASHBOARD_MAX_PREDICTIONS` | 3000 | dashboard-api — max predictions loaded |
| `DASHBOARD_MAX_IP_DETAILS` | 1500 | dashboard-api — max events per IP drill-down |
| `DASHBOARD_DATASET_MAX_AGE_SECONDS` | 8 | dashboard-api — cache TTL in seconds |
| `ROUTER_SESSION_TTL_SECONDS` | 1800 | http-proxy — session stickiness window (30 min) |
| `REBUILD_MAX_LINES_PER_SOURCE` | 5000 | pipeline — max lines read per log file |
| `REBUILD_MAX_SSH_FILES` | 7 | pipeline — max Cowrie log files to process |
| `REBUILD_PROTOCOL_FILTER` | http,mqtt,rtsp,ssh | pipeline — protocols to include |
| `OMP_NUM_THREADS` | 1 | ml-engine / dashboard-api — prevent numpy thread explosion |
| `OPENBLAS_NUM_THREADS` | 1 | ml-engine |
| `LOG_PATH` | /logs/http_honeypot.jsonl | http-honeypot |

---

*Project: IoT Honeypot Capstone — multi-protocol deception system with ML-based attack classification.*
