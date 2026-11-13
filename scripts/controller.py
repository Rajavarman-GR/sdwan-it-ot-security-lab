#!/usr/bin/env python3
"""
controller.py — runs inside the branch_rtr namespace.

Monitors the primary WAN path (WAN1) by pinging hq_rtr's WAN1 address.
If loss crosses FAILOVER_LOSS_PCT, it moves the default route for the HQ
network (10.10.9.0/24) onto WAN2. When WAN1 recovers below RECOVER_LOSS_PCT
it moves back. Every transition is logged as an alert for the dashboard
and for the report.

Run as:  ip netns exec branch_rtr python3 scripts/controller.py
"""
import subprocess
import sys
import time
import re

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from alert_logger import log_alert, set_state

WAN1_PEER = "10.0.1.2"
HQ_NET = "10.10.9.0/24"
WAN1_DEV = "wan1-br"
WAN2_DEV = "wan2-br"
WAN2_PEER = "10.0.2.2"

PING_COUNT = 5
PING_DEADLINE = 2
POLL_INTERVAL = 3
FAILOVER_LOSS_PCT = 30
RECOVER_LOSS_PCT = 10


def ping_loss_pct(target: str) -> float:
    try:
        out = subprocess.run(
            ["ping", "-c", str(PING_COUNT), "-W", "1", "-i", "0.2", "-w",
             str(PING_DEADLINE), target],
            capture_output=True, text=True, timeout=PING_DEADLINE + 2,
        ).stdout
    except Exception:
        return 100.0
    m = re.search(r"(\d+)% packet loss", out)
    if not m:
        return 100.0
    return min(100.0, float(m.group(1)))


def set_route(dev: str, gw: str):
    subprocess.run(["ip", "route", "del", HQ_NET], capture_output=True)
    subprocess.run(["ip", "route", "add", HQ_NET, "via", gw, "dev", dev],
                    capture_output=True)


def main():
    active = "WAN1"
    set_state(active_path=active, wan1_loss_pct=0.0)
    log_alert("controller", "info", "Controller started. Active path: WAN1")

    while True:
        loss = ping_loss_pct(WAN1_PEER)
        set_state(wan1_loss_pct=loss)

        if active == "WAN1" and loss >= FAILOVER_LOSS_PCT:
            set_route(WAN2_DEV, WAN2_PEER)
            active = "WAN2"
            set_state(active_path=active)
            log_alert(
                "controller", "warning",
                f"WAN1 degraded (loss={loss:.0f}%). Failing over to WAN2.",
                wan1_loss_pct=loss,
            )
        elif active == "WAN2" and loss <= RECOVER_LOSS_PCT:
            set_route(WAN1_DEV, WAN1_PEER)
            active = "WAN1"
            set_state(active_path=active)
            log_alert(
                "controller", "info",
                f"WAN1 recovered (loss={loss:.0f}%). Failing back to WAN1.",
                wan1_loss_pct=loss,
            )
        else:
            print(f"[controller] active={active} wan1_loss={loss:.0f}%")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
