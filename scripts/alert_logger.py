"""
alert_logger.py
Shared logging utility for the controller and all detection scripts.

Every alert is appended as one JSON line to logs/alerts.jsonl (used by the
dashboard) and also printed to stdout / written to a plain-text log for the
report screenshots.
"""
import json
import os
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

JSONL_PATH = os.path.join(LOG_DIR, "alerts.jsonl")
TEXT_PATH = os.path.join(LOG_DIR, "alerts.log")
STATE_PATH = os.path.join(LOG_DIR, "state.json")


def log_alert(source: str, severity: str, message: str, **extra):
    """
    source   : which component raised it, e.g. "flood_detector"
    severity : "info" | "warning" | "critical"
    message  : human-readable description
    extra    : any additional structured fields (attacker_ip, path, etc.)
    """
    event = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source": source,
        "severity": severity,
        "message": message,
        **extra,
    }
    with open(JSONL_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")
    with open(TEXT_PATH, "a") as f:
        f.write(f"[{event['timestamp']}] ({severity.upper()}) {source}: {message}\n")
    print(f"[{event['timestamp']}] ({severity.upper()}) {source}: {message}")
    return event


def set_state(**fields):
    """Persist small bits of shared state (active WAN path, etc.) for the dashboard."""
    state = {}
    if os.path.exists(STATE_PATH):
        try:
            with open(STATE_PATH) as f:
                state = json.load(f)
        except Exception:
            state = {}
    state.update(fields)
    state["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(STATE_PATH, "w") as f:
        json.dump(state, f, indent=2)
    return state


def get_state():
    if os.path.exists(STATE_PATH):
        try:
            with open(STATE_PATH) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def read_alerts(limit=200):
    if not os.path.exists(JSONL_PATH):
        return []
    with open(JSONL_PATH) as f:
        lines = f.readlines()[-limit:]
    out = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out
