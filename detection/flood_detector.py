#!/usr/bin/env python3
"""
flood_detector.py — Detector for Attack 1 (link flooding).

Runs inside branch_rtr. Sniffs traffic entering from the IT and OT zones
(itlink, otlink) on its way out to the WAN, counts packets per source IP in
a sliding window, and raises an alert + blocks the source with iptables if
the rate crosses a threshold. This is independent of controller.py's WAN
health-check / failover: this script is the security detection + response
layer, the controller is the network-resilience layer. Running both shows
how an SD-WAN's availability response (failover) and a SOC-style response
(detect + block the attacker) complement each other.

Run as:  ip netns exec branch_rtr python3 detection/flood_detector.py
"""
import subprocess
import sys
import threading
import time
from collections import defaultdict

from scapy.all import sniff, IP

sys.path.insert(0, __file__.rsplit("/", 1)[0].rsplit("/", 1)[0] + "/scripts")
from alert_logger import log_alert, set_state  # noqa: E402

WINDOW_SECONDS = 2
PPS_THRESHOLD = 300          # packets/sec from one source to call it a flood
IFACES = ["itlink", "otlink"]

_counts = defaultdict(int)
_lock = threading.Lock()
_blocked = set()


def _on_packet(pkt):
    if IP in pkt:
        with _lock:
            _counts[pkt[IP].src] += 1


def block_source(ip: str):
    if ip in _blocked:
        return
    _blocked.add(ip)
    subprocess.run(["iptables", "-I", "FORWARD", "1", "-s", ip, "-j", "DROP"],
                    capture_output=True)
    log_alert("flood_detector", "critical",
              f"Blocked {ip} at branch_rtr (iptables FORWARD DROP) after "
              f"sustained flood.", attacker_ip=ip)


def monitor_loop():
    while True:
        time.sleep(WINDOW_SECONDS)
        with _lock:
            snapshot = dict(_counts)
            _counts.clear()
        for src, count in snapshot.items():
            pps = count / WINDOW_SECONDS
            if pps >= PPS_THRESHOLD:
                log_alert(
                    "flood_detector", "warning",
                    f"Link flooding suspected from {src} (~{pps:.0f} pkt/s).",
                    attacker_ip=src, pps=round(pps, 1),
                )
                block_source(src)


def main():
    log_alert("flood_detector", "info",
               f"Flood detector started (threshold={PPS_THRESHOLD} pps, "
               f"window={WINDOW_SECONDS}s) on {IFACES}.")
    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()
    sniff(iface=IFACES, prn=_on_packet, store=False)


if __name__ == "__main__":
    main()
