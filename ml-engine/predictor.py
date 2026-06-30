"""
predictor.py — IoT Honeypot ML Engine
Ain Shams University — Cybersecurity Graduation Project 2026

Runs every 60 seconds, reads honeypot logs, extracts features,
predicts attack type, and writes enriched output to predictions.jsonl

UPDATE: Model now uses 5-category labels (Normal, Scanning, Brute_Force,
DDoS, Exploit_Attempt) trained on CIC IoT 2023 + UNSW-NB15.
Rule-based override layer handles HTTP-only feature sparsity.
"""

import os
import json
import time
import shutil
import joblib
import requests
import threading
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime, timezone

from feature_extractor import extract_features

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

CONFIG_PATH = Path(__file__).parent / "config.json"

with open(CONFIG_PATH) as f:
    CONFIG = json.load(f)

MODEL_PATH      = Path(CONFIG["model_path"])
ENCODER_PATH    = Path(CONFIG["encoder_path"])
SCALER_PATH     = Path(CONFIG["scaler_path"])
COLUMNS_PATH    = Path(CONFIG["columns_path"])
OUTPUT_PATH     = Path(CONFIG["output_path"])
OFFENDER_PATH   = Path(CONFIG["output_path"]).parent / "offender_history.json"
RUN_EVERY       = CONFIG.get("run_every_seconds", 60)

# Read every log file listed in config.json (not just http/ssh/mqtt) so the
# predictor scores all protocols and normal users, not only honeypot traffic.
LOG_FILES = {service: Path(path) for service, path in CONFIG["log_files"].items()}

# ─────────────────────────────────────────────
# LOAD MODEL
# ─────────────────────────────────────────────

print("🔄 Loading model files...")
model           = joblib.load(MODEL_PATH)
le_category     = joblib.load(ENCODER_PATH)   # native model encoder (may be fine-grained)
scaler          = joblib.load(SCALER_PATH)
feature_columns = joblib.load(COLUMNS_PATH)
print("✅ Model loaded successfully")
print(f"   Categories : {list(le_category.classes_)}")
print(f"   Features   : {len(feature_columns)}\n")

# ─────────────────────────────────────────────
# CATEGORY MAPPING
# The model may emit fine-grained CIC-IoT-2023-style labels
# (e.g. "DDoS-SYN_Flood", "Recon-PortScan", "Mirai-udpplain").
# Everything downstream (risk level, recommendations, attacker
# profile, kill chain) only understands the 5 coarse categories
# below, so every native label is bucketed into one of them.
# ─────────────────────────────────────────────

CATEGORY_MAP = {
    # Normal
    'Normal'           : 'Normal',
    'BenignTraffic'     : 'Normal',

    # DDoS / DoS / Mirai botnet floods
    'DDoS'                          : 'DDoS',
    'DDoS-ACK_Fragmentation'        : 'DDoS',
    'DDoS-HTTP_Flood'               : 'DDoS',
    'DDoS-ICMP_Flood'                : 'DDoS',
    'DDoS-ICMP_Fragmentation'        : 'DDoS',
    'DDoS-PSHACK_Flood'              : 'DDoS',
    'DDoS-RSTFINFlood'               : 'DDoS',
    'DDoS-SYN_Flood'                 : 'DDoS',
    'DDoS-SlowLoris'                 : 'DDoS',
    'DDoS-SynonymousIP_Flood'        : 'DDoS',
    'DDoS-TCP_Flood'                 : 'DDoS',
    'DDoS-UDP_Flood'                 : 'DDoS',
    'DDoS-UDP_Fragmentation'         : 'DDoS',
    'DoS-HTTP_Flood'                 : 'DDoS',
    'DoS-SYN_Flood'                  : 'DDoS',
    'DoS-TCP_Flood'                  : 'DDoS',
    'DoS-UDP_Flood'                  : 'DDoS',
    'Mirai-greeth_flood'             : 'DDoS',
    'Mirai-greip_flood'              : 'DDoS',
    'Mirai-udpplain'                 : 'DDoS',

    # Reconnaissance / scanning
    'Scanning'              : 'Scanning',
    'Recon-HostDiscovery'   : 'Scanning',
    'Recon-OSScan'          : 'Scanning',
    'Recon-PingSweep'       : 'Scanning',
    'Recon-PortScan'        : 'Scanning',
    'VulnerabilityScan'     : 'Scanning',

    # Credential attacks
    'Brute_Force'           : 'Brute_Force',
    'DictionaryBruteForce'  : 'Brute_Force',

    # Exploitation / malware / injection / spoofing
    'Exploit_Attempt'    : 'Exploit_Attempt',
    'Backdoor_Malware'   : 'Exploit_Attempt',
    'BrowserHijacking'   : 'Exploit_Attempt',
    'CommandInjection'   : 'Exploit_Attempt',
    'SqlInjection'       : 'Exploit_Attempt',
    'XSS'                : 'Exploit_Attempt',
    'MITM-ArpSpoofing'   : 'Exploit_Attempt',
    'DNS_Spoofing'       : 'Exploit_Attempt',
}

def map_to_category(native_label):
    return CATEGORY_MAP.get(native_label, 'Scanning')

# ─────────────────────────────────────────────
# RISK LEVEL
# Now based on 5 categories instead of 34 detailed classes
# ─────────────────────────────────────────────

def get_risk_level(predicted_attack, confidence):
    if predicted_attack == 'Normal':
        return 'None'
    elif predicted_attack == 'DDoS':
        base = 'High'
    elif predicted_attack == 'Exploit_Attempt':
        base = 'High'
    elif predicted_attack == 'Brute_Force':
        base = 'Medium'
    elif predicted_attack == 'Scanning':
        base = 'Low'
    else:
        base = 'Low'

    # Downgrade if model is uncertain
    if confidence < 0.50:
        if base == 'High':
            return 'Medium'
        elif base == 'Medium':
            return 'Low'

    return base

# ─────────────────────────────────────────────
# CONFIDENCE BAND
# ─────────────────────────────────────────────

def get_confidence_band(confidence):
    if confidence >= 0.85:
        return 'Very High'
    elif confidence >= 0.70:
        return 'High'
    elif confidence >= 0.50:
        return 'Medium'
    else:
        return 'Low'

# ─────────────────────────────────────────────
# RECOMMENDATIONS
# Now mapped to 5 categories
# ─────────────────────────────────────────────

RECOMMENDATIONS = {
    'DDoS'            : 'Block IP immediately, enable rate limiting and SYN cookies, review firewall rules',
    'Exploit_Attempt' : 'Block IP immediately, audit exposed endpoints, check for successful exploitation, run malware scan',
    'Brute_Force'     : 'Block IP, enforce account lockout policy, enable MFA, review exposed login endpoints',
    'Scanning'        : 'Block IP, review exposed services, close unnecessary ports, check firewall rules',
    'Normal'          : 'No action required — normal traffic',
}

def get_recommendation(predicted_attack):
    return RECOMMENDATIONS.get(
        predicted_attack,
        'Monitor traffic, consider blocking IP if behavior continues'
    )

# ─────────────────────────────────────────────
# BORDERLINE SCANNING
# A "Scanning" verdict can fire on scanner-path hits alone (Rule 4) even for a
# slow, normal user just browsing. Without the rate/volume of an active scan
# (high requests/min or many 404s) this sits *between* normal and suspicious.
# Keep the Scanning label, but cap confidence to Medium and recommend
# monitoring instead of an immediate block.
# ─────────────────────────────────────────────

BORDERLINE_SCAN_RPM_MAX        = 5.0
BORDERLINE_SCAN_404_MAX        = 15
BORDERLINE_SCAN_CONFIDENCE_CAP = 0.55
BORDERLINE_SCAN_RECOMMENDATION = (
    'Monitor / investigate; activity is low-and-slow and may be a normal user. '
    'Block only if request rate or error volume increases.'
)

def is_borderline_scanning(predicted_attack, features):
    if predicted_attack != 'Scanning':
        return False
    # A real hit on a sensitive/admin path is deliberate recon — capture it,
    # never soften it to "may be a normal user". Borderline only covers the
    # ambiguous 404-noise case (no real sensitive-path access).
    if (features.get('scanner_path_real_hits', 0) or 0) >= 1:
        return False
    rpm        = features.get('requests_per_min', 0) or 0
    status_404 = features.get('status_404_count', 0) or 0
    return rpm < BORDERLINE_SCAN_RPM_MAX and status_404 < BORDERLINE_SCAN_404_MAX

# ─────────────────────────────────────────────
# ML CONFIDENCE FLOOR  (broken-model guard)
# The sklearn model was trained on CIC-IoT 2023 network-flow features
# (flow_duration, syn_flag_number, packet-size stats, …) which the honeypot's
# application-layer logs cannot supply. After reindexing, every IP is fed an
# all-zero vector, so the model returns a constant near-baseline prediction
# (~1/n_classes ≈ 0.03 confidence). Treat any ML-only verdict below this floor
# as inconclusive (Normal / no action) and let the rule layer be the authority.
# Rule-based verdicts (overridden=True) are never touched by this. The raw model
# output is preserved in ml_prediction / ml_confidence for transparency.
# Override with the ML_MIN_CONFIDENCE env var.
# ─────────────────────────────────────────────

ML_MIN_CONFIDENCE = float(os.environ.get("ML_MIN_CONFIDENCE", "0.30"))
ML_LOW_CONF_RECOMMENDATION = (
    'No action required — ML confidence below threshold (insufficient signal); '
    'rule engine found nothing actionable.'
)

# ─────────────────────────────────────────────
# ATTACKER PROFILE
# Based on features + 5-category prediction
# ─────────────────────────────────────────────

def get_attacker_profile(features, predicted_attack):
    rpm         = features.get('requests_per_min',  0)
    unique_pw   = features.get('unique_passwords',  0)
    cmd_count   = features.get('command_count',     0)
    has_exploit = features.get('has_exploit',       0)
    login_att   = features.get('login_attempts',    0)

    if predicted_attack == 'DDoS':
        if rpm > 100:
            return 'Automated DDoS Bot'
        else:
            return 'DDoS Bot'
    elif predicted_attack == 'Exploit_Attempt':
        if cmd_count > 5 and has_exploit:
            return 'Manual Attacker'
        else:
            return 'Exploit Bot'
    elif predicted_attack == 'Brute_Force':
        if unique_pw > 10:
            return 'Credential Stuffing Bot'
        else:
            return 'Brute Force Bot'
    elif predicted_attack == 'Scanning':
        return 'Scanner'
    else:
        return 'Normal User'

# ─────────────────────────────────────────────
# KILL CHAIN STAGE
# Mapped to 5 categories
# ─────────────────────────────────────────────

KILL_CHAIN_MAP = {
    'Scanning'        : 'Reconnaissance',
    'Brute_Force'     : 'Weaponization',
    'Exploit_Attempt' : 'Exploitation',
    'DDoS'            : 'Actions on Objectives',
    'Normal'          : 'None',
}

def get_kill_chain_stage(predicted_attack):
    return KILL_CHAIN_MAP.get(predicted_attack, 'Unknown')

# ─────────────────────────────────────────────
# GEOLOCATION
# FIX 5 — ip-api.com free tier allows ~45 requests/minute.
# Without throttling, a cycle with many new IPs can blow through
# that limit and start silently getting failed/empty responses.
# A simple lock + minimum-interval sleep keeps every call spaced
# out safely, while the cache still avoids re-querying known IPs.
# ─────────────────────────────────────────────

_geo_cache        = {}
_geo_lock         = threading.Lock()
_last_geo_call    = 0.0
_GEO_MIN_INTERVAL = 1.5   # seconds between calls -> well under 45/min

# Persist the geo cache to disk. Without this the in-memory cache is empty on
# every restart, so a cycle re-queries every IP at 1.5s each — with thousands
# of IPs a single cycle takes over an hour and never completes, which is why
# predictions.jsonl used to go stale. Loading the cache makes restarts instant.
GEO_CACHE_PATH    = Path(CONFIG["output_path"]).parent / "geo_cache.json"
try:
    if GEO_CACHE_PATH.exists():
        with open(GEO_CACHE_PATH) as _gf:
            _geo_cache = json.load(_gf)
except Exception:
    _geo_cache = {}

def _save_geo_cache():
    try:
        tmp = GEO_CACHE_PATH.with_name(GEO_CACHE_PATH.name + ".tmp")
        with open(tmp, "w") as _gf:
            json.dump(_geo_cache, _gf)
        os.replace(tmp, GEO_CACHE_PATH)
    except Exception:
        pass

def get_geolocation(ip, allow_lookup=True):
    if ip in _geo_cache:
        return _geo_cache[ip]

    # Non-blocking path: used during the prediction loop so the ML verdict is
    # written immediately instead of waiting on a 1.5s external geo lookup.
    if not allow_lookup:
        return {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}

    global _last_geo_call
    with _geo_lock:
        elapsed = time.time() - _last_geo_call
        if elapsed < _GEO_MIN_INTERVAL:
            time.sleep(_GEO_MIN_INTERVAL - elapsed)
        _last_geo_call = time.time()

        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}?fields=country,city,isp",
                timeout=3
            )
            data = response.json()
            if data.get('status') == 'fail':
                result = {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}
            else:
                result = {
                    "country": data.get("country", "Unknown"),
                    "city"   : data.get("city",    "Unknown"),
                    "isp"    : data.get("isp",     "Unknown"),
                }
        except Exception:
            result = {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}

    _geo_cache[ip] = result
    return result

# ─────────────────────────────────────────────
# REPEAT OFFENDER TRACKING
# ─────────────────────────────────────────────

# Offender history is loaded once per process and mutated in memory. Writing it
# on every IP (a full read + full rewrite of the whole file) was an O(n^2)
# per-cycle bottleneck that made cycles take many MINUTES with thousands of IPs
# under memory pressure — freezing the dashboard's ML data. We now load once and
# save once per cycle (see _save_offender_history(), called at cycle end).
_offender_history = None

def _load_offender_history():
    global _offender_history
    if _offender_history is None:
        _offender_history = {}
        if OFFENDER_PATH.exists():
            try:
                with open(OFFENDER_PATH) as f:
                    _offender_history = json.load(f)
            except Exception:
                _offender_history = {}
    return _offender_history

def _save_offender_history():
    if _offender_history is None:
        return
    try:
        tmp = OFFENDER_PATH.with_name(OFFENDER_PATH.name + ".tmp")
        with open(tmp, 'w') as f:
            json.dump(_offender_history, f, indent=2)
        os.replace(tmp, OFFENDER_PATH)
    except Exception as e:
        print(f"  ⚠️ Could not save offender history: {e}")

def get_offender_info(ip, predicted_attack, timestamp):
    history = _load_offender_history()

    # Count distinct visits, not 60s prediction cycles: only bump times_seen
    # when the source returns after a quiet gap (default 30 min, matching the
    # router session window). Otherwise a continuously-active IP inflates to
    # hundreds/thousands of "sightings".
    gap_seconds = int(os.environ.get("OFFENDER_SESSION_GAP_SECONDS", "1800") or "1800")

    def _parse_ts(value):
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except Exception:
            return None

    if ip not in history:
        history[ip] = {
            'first_seen' : timestamp,
            'last_seen'  : timestamp,
            'times_seen' : 1,
            'attacks'    : [predicted_attack]
        }
        is_repeat = False
    else:
        entry = history[ip]
        prev = _parse_ts(entry.get('last_seen') or entry.get('first_seen'))
        now  = _parse_ts(timestamp)
        if prev is None or now is None or (now - prev).total_seconds() >= gap_seconds:
            entry['times_seen'] = int(entry.get('times_seen', 1)) + 1
        entry['last_seen'] = timestamp
        entry.setdefault('attacks', [])
        if predicted_attack not in entry['attacks']:
            entry['attacks'].append(predicted_attack)
        is_repeat = int(entry.get('times_seen', 1)) > 1

    # NOTE: no file write here — the in-memory dict is persisted once per cycle
    # by _save_offender_history() to avoid O(n^2) I/O over thousands of IPs.
    return {
        'is_repeat_offender': is_repeat,
        'first_seen'        : history[ip]['first_seen'],
        'times_seen'        : history[ip]['times_seen'],
    }

# ─────────────────────────────────────────────
# RULE-BASED OVERRIDE
# Compensates for feature sparsity in HTTP-only logs.
# Rules now map to 5 category names to match the model.
# ─────────────────────────────────────────────

def apply_rule_override(predicted_attack, features, confidence):
    """
    Apply rule-based classification on top of ML prediction.
    Rules fire when HTTP log signals are unambiguous.
    Returns (final_attack, final_confidence, was_overridden)
    """
    rpm          = features.get('requests_per_min',  0)
    status_404   = features.get('status_404_count',  0)
    status_401   = features.get('status_401_count',  0)
    has_exploit  = features.get('has_exploit',       0)
    scanner_hits = features.get('scanner_path_hits', 0)
    total        = features.get('total_events',      0)
    status_200   = features.get('status_200_count',  0)
    unique_pw    = features.get('unique_passwords',  0)

    # Rule 1 — Many 401s = brute force
    if status_401 >= 5:
        return 'Brute_Force', 0.88, True

    # Rule 2 — High rate + many 404s = scanning
    if status_404 >= 5 and rpm > 10:
        return 'Scanning', 0.85, True

    # Rule 3 — Exploit strings in payload or command
    if has_exploit:
        return 'Exploit_Attempt', 0.85, True

    # Rule 4 — Scanner path access = reconnaissance.
    # A single REAL hit on a known sensitive/admin path (e.g. /admin, /wp-admin)
    # is a deliberate recon action → flag on hit #1. The 404-inflation fallback
    # (scanner_hits derived from many 404s) still needs the old >=3 threshold so
    # ordinary low-and-slow browsing isn't hard-flagged.
    scanner_real = features.get('scanner_path_real_hits', 0)
    if scanner_real >= 1 or scanner_hits >= 3:
        return 'Scanning', 0.82, True

    # Rule 5 — Multiple unique passwords = credential stuffing
    if unique_pw >= 5:
        return 'Brute_Force', 0.80, True

    # Rule 6 — Very few events, got a 200, no threats = normal
    if total <= 3 and status_200 >= 1 and status_404 == 0 and status_401 == 0:
        return 'Normal', 0.75, True

    # Rule 7 — Single 404, no other signals = normal probe
    if total <= 2 and status_404 == 1 and status_401 == 0:
        return 'Normal', 0.65, True

    # No rule fired — trust the ML model
    return predicted_attack, confidence, False


# ─────────────────────────────────────────────
# MAIN PREDICTION LOOP
# ─────────────────────────────────────────────

def run_prediction_cycle():
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    print(f"\n{'─'*60}")
    print(f"🔍 Prediction cycle: {timestamp}")

    # ── Extract features ──
    feature_rows = extract_features(LOG_FILES)

    if not feature_rows:
        print("   No events found in logs — skipping cycle")
        return

    # Process most-recently-active IPs first so live attackers (the ones shown
    # on the dashboard) get predicted and published at the start of the cycle,
    # before any slow geo lookups for stale IPs further down the list.
    feature_rows.sort(key=lambda r: r.get("_last_seen", ""), reverse=True)

    # Optional safety cap for this small box: only predict the N most-recent IPs
    # per cycle (0 = unlimited). Keeps cycle time and memory bounded.
    max_ips = int(os.environ.get("PREDICTOR_MAX_IPS", "0") or "0")
    if max_ips > 0 and len(feature_rows) > max_ips:
        print(f"   Capping cycle to {max_ips} most-recent IPs (of {len(feature_rows)})")
        feature_rows = feature_rows[:max_ips]

    print(f"   IPs to predict: {len(feature_rows)}")

    # ── Build feature dataframe ──
    df      = pd.DataFrame(feature_rows)
    ip_list = df['source_ip'].tolist()
    X       = df.drop(columns=['source_ip'], errors='ignore')

    # Align to training feature columns
    X = X.reindex(columns=feature_columns, fill_value=0)
    X = X.replace([float('inf'), float('-inf')], 0).fillna(0)

    # Scale
    X_scaled = scaler.transform(X)

    # ── ML Predict ──
    probabilities  = model.predict_proba(X_scaled)
    predicted_idxs = np.argmax(probabilities, axis=1)
    confidences    = np.max(probabilities, axis=1)
    native_predictions = le_category.inverse_transform(predicted_idxs)  # native model labels
    predictions    = [map_to_category(label) for label in native_predictions]  # bucketed to 5 categories

    # ── Build enriched output ──
    # Build the entire cycle in a temp .building file, then publish it to
    # predictions.jsonl with a single atomic os.replace at the end. We do NOT
    # publish partial snapshots mid-cycle: with thousands of IPs rebuilt from
    # scratch each cycle, an incomplete file made each source's ML data flicker
    # in and out on the dashboard. Until the swap, predictions.jsonl keeps the
    # previous COMPLETE cycle, so every read sees a full, consistent IP set.
    results = []
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    build_path = OUTPUT_PATH.with_name(OUTPUT_PATH.name + ".building")
    PUBLISH_EVERY = 200

    def _publish_snapshot():
        try:
            build_f.flush()
            os.fsync(build_f.fileno())
            snap = OUTPUT_PATH.with_name(OUTPUT_PATH.name + ".publish.tmp")
            shutil.copyfile(build_path, snap)
            os.replace(snap, OUTPUT_PATH)
        except Exception as pub_err:
            print(f"   ⚠️  snapshot publish skipped: {pub_err}")

    # ── Carry-over: remember each IP's last ML result ──
    # predictions.jsonl is rebuilt every cycle from only the currently-active
    # IPs, so a source's ML details vanish once it goes quiet. Load the previous
    # cycle's rows now and re-emit the ones not scored this cycle (bounded to the
    # most-recent PREDICTOR_RETAIN_MAX entries; 0 disables carry-over).
    retain_max = int(os.environ.get("PREDICTOR_RETAIN_MAX", "5000") or "0")
    current_ips = set(ip_list)
    carried = []
    if retain_max != 0 and OUTPUT_PATH.exists():
        try:
            with open(OUTPUT_PATH) as _pf:
                for _line in _pf:
                    _line = _line.strip()
                    if not _line:
                        continue
                    try:
                        _row = json.loads(_line)
                    except json.JSONDecodeError:
                        continue
                    _ip = _row.get("source_ip")
                    if _ip and _ip not in current_ips:
                        _row["carried_over"] = True
                        carried.append(_row)
        except OSError:
            carried = []
        carried.sort(key=lambda r: r.get("timestamp_utc", ""), reverse=True)
        if retain_max > 0:
            carried = carried[:max(0, retain_max - len(current_ips))]

    build_f = open(build_path, 'w')
    pending_geo_ips = []

    # Write carried-over predictions (IPs not active this cycle) FIRST so every
    # snapshot published during the cycle already contains the full known IP set.
    # Without this the file shrinks to just the freshly-scored IPs mid-cycle, so a
    # source's ML data flickers in and out on the dashboard while the cycle works
    # through thousands of IPs. `carried` is disjoint from the active IPs, so the
    # fresh rows written below never duplicate these.
    for _row in carried:
        build_f.write(json.dumps(_row) + '\n')

    for i, ip in enumerate(ip_list):
        ml_attack        = predictions[i]
        ml_attack_native = native_predictions[i]
        ml_conf          = float(confidences[i])
        features         = feature_rows[i]

        # Apply rule-based override
        predicted_attack, confidence, overridden = apply_rule_override(
            ml_attack, features, ml_conf
        )

        # ML confidence floor: the model is fed all-zero vectors on honeypot
        # features and returns near-baseline noise, so an ML-only verdict below
        # the floor is inconclusive — treat as Normal and defer to the rules.
        ml_low_confidence = (not overridden) and confidence < ML_MIN_CONFIDENCE
        if ml_low_confidence:
            predicted_attack = 'Normal'

        # Borderline scanning (path hits but no active-scan rate/volume): lower
        # the reported confidence so risk and band reflect the uncertainty.
        borderline_scan = is_borderline_scanning(predicted_attack, features)
        if borderline_scan and confidence > BORDERLINE_SCAN_CONFIDENCE_CAP:
            confidence = BORDERLINE_SCAN_CONFIDENCE_CAP

        # Enrichment
        risk_level       = get_risk_level(predicted_attack, confidence)
        confidence_band  = get_confidence_band(confidence)
        recommendation   = get_recommendation(predicted_attack)
        if borderline_scan:
            recommendation = BORDERLINE_SCAN_RECOMMENDATION
        elif ml_low_confidence:
            recommendation = ML_LOW_CONF_RECOMMENDATION

        # Deliberate access to a sensitive/admin path is notable reconnaissance.
        # Surface it at Medium so it's visibly "captured" on the dashboard rather
        # than buried at Scanning's default Low risk.
        if predicted_attack == 'Scanning' and (features.get('scanner_path_real_hits', 0) or 0) >= 1:
            if risk_level == 'Low':
                risk_level = 'Medium'
        attacker_profile = get_attacker_profile(features, predicted_attack)
        kill_chain_stage = get_kill_chain_stage(predicted_attack)
        # Cache-only here so the ML verdict is written without blocking on a
        # 1.5s geo lookup; cache misses are enriched after the cycle publishes.
        geo              = get_geolocation(ip, allow_lookup=False)
        if ip not in _geo_cache:
            pending_geo_ips.append(ip)
        offender_info    = get_offender_info(ip, predicted_attack, timestamp)

        entry = {
            # ── Identity ──
            "timestamp_utc"        : timestamp,
            "source_ip"            : ip,

            # ── Prediction ──
            "predicted_attack"     : predicted_attack,
            "confidence"           : round(confidence, 4),
            "confidence_band"      : confidence_band,

            # ── Classification method ──
            "detection_method"     : "rule_based" if overridden else "ml_model",
            "ml_prediction"        : ml_attack,
            "ml_prediction_native" : ml_attack_native,
            "ml_confidence"        : round(ml_conf, 4),
            "overridden_by_rules"  : overridden,
            "ml_low_confidence"    : ml_low_confidence,

            # ── Risk & Action ──
            "risk_level"           : risk_level,
            "recommendation"       : recommendation,

            # ── Attacker Intelligence ──
            "attacker_profile"     : attacker_profile,
            "kill_chain_stage"     : kill_chain_stage,

            # ── Repeat Offender ──
            "is_repeat_offender"   : offender_info['is_repeat_offender'],
            "first_seen"           : offender_info['first_seen'],
            "times_seen"           : offender_info['times_seen'],

            # ── Geolocation ──
            "geo"                  : geo,

            # ── Raw Features ──
            "total_events"         : int(features.get('total_events',        0)),
            "requests_per_min"     : round(float(features.get('requests_per_min', 0)), 2),
            "login_attempts"       : int(features.get('login_attempts',      0)),
            "unique_usernames"     : int(features.get('unique_usernames',    0)),
            "unique_passwords"     : int(features.get('unique_passwords',    0)),
            "has_credentials"      : int(features.get('has_credentials',     0)),
            "has_exploit"          : int(features.get('has_exploit',         0)),
            "exploit_in_payload"   : int(features.get('exploit_in_payload',  0)),
            "exploit_in_command"   : int(features.get('exploit_in_command',  0)),
            "command_count"        : int(features.get('command_count',       0)),
            "file_download_count"  : int(features.get('file_download_count', 0)),
            "status_404_count"     : int(features.get('status_404_count',    0)),
            "status_401_count"     : int(features.get('status_401_count',    0)),
            "scanner_path_hits"    : int(features.get('scanner_path_hits',   0)),
            "scanner_path_real_hits": int(features.get('scanner_path_real_hits', 0)),
        }

        results.append(entry)

        # Stream each prediction to the building file; the completed file is
        # published atomically once at the end of the cycle.
        build_f.write(json.dumps(entry) + '\n')

        # Console summary — must never abort the cycle (a formatting error here
        # would otherwise interrupt streaming of the remaining predictions).
        try:
            override_tag = " [RULE]" if overridden else " [ML]  "
            risk_icon    = {'High': '🔴', 'Medium': '🟠', 'Low': '🟡', 'None': '🟢'}.get(risk_level, '⚪')
            safe_conf     = float(confidence) if confidence is not None else 0.0
            safe_ip       = str(ip) if ip is not None else "unknown"
            safe_attack   = str(predicted_attack) if predicted_attack is not None else "Unknown"
            safe_country  = (geo or {}).get('country') or "Unknown"
            print(f"   {risk_icon}{override_tag} {safe_ip:<18} → {safe_attack:<20} "
                  f"conf: {safe_conf:.2f} | {risk_level} | {safe_country}")
        except Exception as console_err:
            print(f"   ⚪ [LOG]  {ip} → {predicted_attack} (console summary skipped: {console_err})")

    # (Carried-over predictions for quiet IPs were written BEFORE the scoring
    # loop so every mid-cycle snapshot already contains the full IP set.)

    # ── Final publish ──
    _publish_snapshot()
    build_f.close()
    _save_geo_cache()
    _save_offender_history()
    try:
        os.remove(build_path)
    except OSError:
        pass

    # ── Geolocation enrichment (AFTER predictions are published) ──
    # Fill geo for new IPs without blocking the ML verdict. Bounded per cycle so
    # the enrichment pass can't stall the loop on a huge first run; remaining IPs
    # are picked up on later cycles.
    geo_budget = int(os.environ.get("GEO_MAX_LOOKUPS_PER_CYCLE", "60") or "0")
    if geo_budget > 0 and pending_geo_ips:
        done = 0
        for gip in pending_geo_ips:
            if gip in _geo_cache:
                continue
            get_geolocation(gip, allow_lookup=True)
            done += 1
            if done >= geo_budget:
                break
        _save_geo_cache()

    # ── Cycle summary ──
    rule_count = sum(1 for r in results if r['overridden_by_rules'])
    ml_count   = len(results) - rule_count
    print(f"\n   ✅ Written {len(results)} predictions → {OUTPUT_PATH}")
    print(f"      ML classified  : {ml_count}")
    print(f"      Rule overridden: {rule_count}")


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == '__main__':
    print("🚀 IoT Honeypot ML Predictor started")
    print(f"   Categories : {list(le_category.classes_)}")
    print(f"   Output     → {OUTPUT_PATH}")
    print(f"   Running every {RUN_EVERY} seconds\n")

    while True:
        try:
            run_prediction_cycle()
        except Exception as e:
            print(f"  ❌ Cycle error: {e}")

        time.sleep(RUN_EVERY)