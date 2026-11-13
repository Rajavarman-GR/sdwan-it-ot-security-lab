#!/bin/bash
# run_demo.sh — convenience wrapper for the three demo scenarios.
# Must be run as root, after setup_topology.sh.
#
# Usage:
#   bash scripts/run_demo.sh flood
#   bash scripts/run_demo.sh arp
#   bash scripts/run_demo.sh rogue
#   bash scripts/run_demo.sh all

set -e
cd "$(dirname "$0")/.."
mkdir -p logs

run_flood() {
    echo "=== Scenario 1: Link flooding ==="
    rm -f logs/alerts.jsonl logs/alerts.log logs/state.json
    ip netns exec branch_rtr python3 scripts/controller.py \
        > logs/controller_console.log 2>&1 &
    CTRL=$!
    ip netns exec branch_rtr python3 detection/flood_detector.py \
        > logs/flood_detector_console.log 2>&1 &
    DET=$!
    sleep 3
    ip netns exec it_pc python3 attacks/link_flood.py \
        --target 10.10.9.50 --duration 20 --pps 3000 \
        > logs/attack_console.log 2>&1
    sleep 3
    kill "$CTRL" "$DET" 2>/dev/null || true
    echo "Done. See logs/alerts.log"
}

run_arp() {
    echo "=== Scenario 2: ARP spoofing ==="
    python3 detection/arp_detector.py --iface br-it --zone IT \
        > logs/arp_detector_console.log 2>&1 &
    DET=$!
    sleep 2
    ip netns exec it_srv python3 attacks/arp_spoof.py \
        --victim 10.10.1.11 --gateway 10.10.1.1 --duration 15 \
        > logs/arp_attack_console.log 2>&1
    sleep 2
    kill "$DET" 2>/dev/null || true
    echo "Done. See logs/alerts.log"
}

run_rogue() {
    echo "=== Scenario 3: Rogue gateway ==="
    OT_MAC=$(ip netns exec branch_rtr cat /sys/class/net/otlink/address)
    python3 detection/rogue_gateway_detector.py --iface br-ot \
        --gateway-ip 10.10.2.1 --trusted-mac "$OT_MAC" \
        > logs/rogue_gw_detector_console.log 2>&1 &
    DET=$!
    sleep 2
    ip netns exec ot_hmi python3 attacks/rogue_gateway.py \
        --gateway-ip 10.10.2.1 --duration 15 \
        > logs/rogue_gw_attack_console.log 2>&1
    sleep 2
    kill "$DET" 2>/dev/null || true
    echo "Done. See logs/alerts.log"
}

case "$1" in
    flood) run_flood ;;
    arp) run_arp ;;
    rogue) run_rogue ;;
    all) run_flood; run_arp; run_rogue ;;
    *) echo "Usage: $0 {flood|arp|rogue|all}"; exit 1 ;;
esac
