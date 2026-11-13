#!/usr/bin/env python3
"""
rogue_gateway_detector.py — Detector for Attack 3 (rogue gateway).

Runs on the HOST attached to the br-ot bridge. Unlike arp_detector.py
(which flags any IP/MAC conflict), this one watches specifically for
claims of the OT default-gateway IP and compares the claiming MAC against
a trusted baseline captured when the detector starts (branch_rtr's real
otlink MAC). Any other MAC claiming that IP is a rogue-gateway attempt.

Run as:  python3 detection/rogue_gateway_detector.py \
             --iface br-ot --gateway-ip 10.10.2.1 --trusted-mac <branch_rtr otlink MAC>
"""
import argparse
import sys

from scapy.all import sniff, ARP

sys.path.insert(0, __file__.rsplit("/", 1)[0].rsplit("/", 1)[0] + "/scripts")
from alert_logger import log_alert  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="br-ot")
    ap.add_argument("--gateway-ip", default="10.10.2.1")
    ap.add_argument("--trusted-mac", required=True,
                     help="branch_rtr's real otlink MAC, captured at setup time")
    args = ap.parse_args()
    trusted = args.trusted_mac.lower()

    log_alert("rogue_gateway_detector", "info",
              f"Rogue gateway detector started on {args.iface}. "
              f"Trusted MAC for {args.gateway_ip} is {trusted}.")

    def handle(pkt):
        if ARP not in pkt or pkt[ARP].op != 2:
            return
        if pkt[ARP].psrc != args.gateway_ip:
            return
        claiming_mac = pkt[ARP].hwsrc.lower()
        if claiming_mac != trusted:
            log_alert(
                "rogue_gateway_detector", "critical",
                f"Rogue gateway detected: {args.gateway_ip} claimed by "
                f"{claiming_mac}, expected {trusted}.",
                gateway_ip=args.gateway_ip, rogue_mac=claiming_mac,
                trusted_mac=trusted,
            )

    sniff(iface=args.iface, filter="arp", prn=handle, store=False)


if __name__ == "__main__":
    main()
