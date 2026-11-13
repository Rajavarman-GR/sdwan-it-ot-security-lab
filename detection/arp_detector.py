#!/usr/bin/env python3
"""
arp_detector.py — Detector for Attack 2 (ARP spoofing).

Runs on the HOST (not inside a namespace) attached to the br-it bridge,
which sees all ARP traffic crossing the IT zone. It builds an IP->MAC
table from observed ARP replies/announcements and raises an alert the
moment one IP is claimed by two different MAC addresses within the
tracking window — the signature of ARP cache poisoning.

Run as:  python3 detection/arp_detector.py --iface br-it
"""
import argparse
import sys
import time

from scapy.all import sniff, ARP

sys.path.insert(0, __file__.rsplit("/", 1)[0].rsplit("/", 1)[0] + "/scripts")
from alert_logger import log_alert  # noqa: E402

# ip -> (mac, last_seen)
_table = {}
_blocked_macs = set()


def handle_arp(pkt, zone_name):
    if ARP not in pkt or pkt[ARP].op not in (1, 2):
        return
    ip = pkt[ARP].psrc
    mac = pkt[ARP].hwsrc
    if ip == "0.0.0.0":
        return

    prev = _table.get(ip)
    if prev is None:
        _table[ip] = (mac, time.time())
        return

    prev_mac, _ = prev
    if prev_mac.lower() != mac.lower():
        log_alert(
            "arp_detector", "critical",
            f"ARP spoofing suspected in {zone_name}: {ip} was {prev_mac}, "
            f"now claimed by {mac}.",
            victim_or_claimed_ip=ip, previous_mac=prev_mac, new_mac=mac,
            zone=zone_name,
        )
        _blocked_macs.add(mac)
    _table[ip] = (mac, time.time())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="br-it")
    ap.add_argument("--zone", default="IT")
    args = ap.parse_args()

    log_alert("arp_detector", "info",
              f"ARP spoof detector started on {args.iface} ({args.zone} zone).")
    sniff(iface=args.iface, filter="arp", prn=lambda p: handle_arp(p, args.zone),
          store=False)


if __name__ == "__main__":
    main()
