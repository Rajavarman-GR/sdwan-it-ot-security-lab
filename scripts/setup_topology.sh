#!/bin/bash
# setup_topology.sh
# Builds the simulated SD-WAN topology with IT/OT segmentation using Linux
# network namespaces, veth pairs, and Linux bridges. Must be run as root
# on a Linux host/VM with iproute2 and iptables installed.
#
# NOTE ON INTERFACE NAMES: every interface created here uses project-specific
# names (it0, ot0, wan1h, ...) rather than generic names like "eth0". Some
# hosts (including cloud VMs and some containers) reserve "eth0" for the
# machine's real network interface; reusing that name for a virtual link can
# rename or disrupt the host's own connectivity. Keep this naming scheme if
# you adapt the script.
#
# Topology:
#
#   it_pc, it_srv --(br-it)--\                                /--(br-hq)-- hq_srv
#                              [ branch_rtr ]--WAN1--[ hq_rtr ]
#   ot_plc, ot_hmi--(br-ot)--/            \--WAN2--/
#
# branch_rtr routes between the IT/OT zones and HQ over two WAN paths
# (WAN1 = primary, WAN2 = backup) and enforces IT<->OT segmentation.
# hq_rtr terminates both WAN links and forwards to the HQ zone.

set -e

# ---- address plan -----------------------------------------------------
# IT zone:      10.10.1.0/24   gateway 10.10.1.1 (branch_rtr)
# OT zone:      10.10.2.0/24   gateway 10.10.2.1 (branch_rtr)
# WAN1:         10.0.1.0/30    branch_rtr=.1  hq_rtr=.2
# WAN2:         10.0.2.0/30    branch_rtr=.1  hq_rtr=.2
# HQ zone:      10.10.9.0/24   gateway 10.10.9.1 (hq_rtr)

NS="it_pc it_srv ot_plc ot_hmi branch_rtr hq_rtr hq_srv"

echo "[*] Creating network namespaces..."
for ns in $NS; do
    ip netns add "$ns" 2>/dev/null || true
done

# ---- helper: create a device, retrying briefly ------------------------
# Some hypervisors/containers have a short lag between "ip link add"
# returning and the device becoming visible to netlink.
create_wait() {
    desc="$1"; shift
    for attempt in 1 2 3 4 5; do
        "$@" 2>/dev/null && return 0
        sleep 0.3
    done
    echo "FATAL: could not create $desc"; exit 1
}

echo "[*] Creating bridges on the host (br-it, br-ot, br-hq)..."
for br in br-it br-ot br-hq; do
    ip link show "$br" >/dev/null 2>&1 || create_wait "$br" ip link add "$br" type bridge
    ip link set "$br" up
done

# ---- helper: create a veth pair, put one end in a namespace -----------
# add_link <host_if> <ns> <ns_if>
add_link() {
    host_if=$1; ns=$2; ns_if=$3
    ip link show "$host_if" >/dev/null 2>&1 || \
        create_wait "$host_if" ip link add "$host_if" type veth peer name "$ns_if"
    ip link set "$ns_if" netns "$ns"
    ip link set "$host_if" up
}

# IT zone hosts -> br-it
add_link veth-itpc-h   it_pc   it0
add_link veth-itsrv-h  it_srv  it0
ip link set veth-itpc-h  master br-it
ip link set veth-itsrv-h master br-it

# OT zone hosts -> br-ot
add_link veth-otplc-h  ot_plc  ot0
add_link veth-othmi-h  ot_hmi  ot0
ip link set veth-otplc-h master br-ot
ip link set veth-othmi-h master br-ot

# branch_rtr <-> br-it, br-ot
add_link veth-br-it-h  branch_rtr itlink
add_link veth-br-ot-h  branch_rtr otlink
ip link set veth-br-it-h master br-it
ip link set veth-br-ot-h master br-ot

# branch_rtr <-> hq_rtr : two direct veth pairs = WAN1 and WAN2
ip link show wan1-br >/dev/null 2>&1 || create_wait wan1-br ip link add wan1-br type veth peer name wan1-hq
ip link show wan2-br >/dev/null 2>&1 || create_wait wan2-br ip link add wan2-br type veth peer name wan2-hq
ip link set wan1-br netns branch_rtr
ip link set wan2-br netns branch_rtr
ip link set wan1-hq netns hq_rtr
ip link set wan2-hq netns hq_rtr

# hq_rtr <-> br-hq, hq_srv -> br-hq
add_link veth-hqrtr-h  hq_rtr  hqlink
add_link veth-hqsrv-h  hq_srv  hq0
ip link set veth-hqrtr-h master br-hq
ip link set veth-hqsrv-h master br-hq

echo "[*] Assigning addresses..."
ip netns exec it_pc  ip addr add 10.10.1.11/24 dev it0
ip netns exec it_srv ip addr add 10.10.1.12/24 dev it0
ip netns exec ot_plc ip addr add 10.10.2.21/24 dev ot0
ip netns exec ot_hmi ip addr add 10.10.2.22/24 dev ot0
ip netns exec hq_srv ip addr add 10.10.9.50/24 dev hq0

ip netns exec branch_rtr ip addr add 10.10.1.1/24  dev itlink
ip netns exec branch_rtr ip addr add 10.10.2.1/24  dev otlink
ip netns exec branch_rtr ip addr add 10.0.1.1/30   dev wan1-br
ip netns exec branch_rtr ip addr add 10.0.2.1/30   dev wan2-br

ip netns exec hq_rtr ip addr add 10.0.1.2/30  dev wan1-hq
ip netns exec hq_rtr ip addr add 10.0.2.2/30  dev wan2-hq
ip netns exec hq_rtr ip addr add 10.10.9.1/24 dev hqlink

echo "[*] Bringing interfaces up..."
ip netns exec it_pc  bash -c "ip link set lo up; ip link set it0 up"
ip netns exec it_srv bash -c "ip link set lo up; ip link set it0 up"
ip netns exec ot_plc bash -c "ip link set lo up; ip link set ot0 up"
ip netns exec ot_hmi bash -c "ip link set lo up; ip link set ot0 up"
ip netns exec hq_srv bash -c "ip link set lo up; ip link set hq0 up"
ip netns exec branch_rtr bash -c "
  ip link set lo up; ip link set itlink up; ip link set otlink up
  ip link set wan1-br up; ip link set wan2-br up
"
ip netns exec hq_rtr bash -c "
  ip link set lo up; ip link set wan1-hq up; ip link set wan2-hq up; ip link set hqlink up
"

echo "[*] Default routes on end hosts..."
ip netns exec it_pc  ip route add default via 10.10.1.1
ip netns exec it_srv ip route add default via 10.10.1.1
ip netns exec ot_plc ip route add default via 10.10.2.1
ip netns exec ot_hmi ip route add default via 10.10.2.1
ip netns exec hq_srv ip route add default via 10.10.9.1

echo "[*] Routes on hq_rtr back to branch zones (static, HQ side is simple)..."
ip netns exec hq_rtr ip route add 10.10.1.0/24 via 10.0.1.1 dev wan1-hq
ip netns exec hq_rtr ip route add 10.10.2.0/24 via 10.0.1.1 dev wan1-hq

echo "[*] branch_rtr: default route starts on WAN1 (primary path)..."
ip netns exec branch_rtr ip route add 10.10.9.0/24 via 10.0.1.2 dev wan1-br

echo "[*] Enabling forwarding on routers..."
ip netns exec branch_rtr sysctl -qw net.ipv4.ip_forward=1
ip netns exec hq_rtr     sysctl -qw net.ipv4.ip_forward=1

echo "[*] IT/OT segmentation + WAN forwarding rules on branch_rtr..."
ip netns exec branch_rtr bash -c "
  iptables -F FORWARD
  iptables -P FORWARD DROP
  # Allow IT zone <-> WAN (to HQ)
  iptables -A FORWARD -i itlink -o wan1-br -j ACCEPT
  iptables -A FORWARD -i itlink -o wan2-br -j ACCEPT
  iptables -A FORWARD -i wan1-br -o itlink -j ACCEPT
  iptables -A FORWARD -i wan2-br -o itlink -j ACCEPT
  # Allow OT zone <-> WAN (to HQ)
  iptables -A FORWARD -i otlink -o wan1-br -j ACCEPT
  iptables -A FORWARD -i otlink -o wan2-br -j ACCEPT
  iptables -A FORWARD -i wan1-br -o otlink -j ACCEPT
  iptables -A FORWARD -i wan2-br -o otlink -j ACCEPT
  # Explicitly block direct IT <-> OT traffic (segmentation)
  iptables -A FORWARD -i itlink -o otlink -j DROP
  iptables -A FORWARD -i otlink -o itlink -j DROP
"

echo "[*] Shaping WAN links so they behave like real, bandwidth-limited links..."
# Prefer netem (adds realistic delay+a small preference gap between the two
# paths). Some minimal/hardened kernels (certain cloud microVMs/containers)
# do not build sch_netem; this falls back to tbf (a basic bandwidth cap)
# which is virtually always available and still makes link flooding cause
# real, measurable congestion. See docs/LIMITATIONS.md.
shape_link() {
    ns=$1; dev=$2; rate=$3
    if ip netns exec "$ns" tc qdisc add dev "$dev" root netem delay "${rate}ms" 2>/dev/null; then
        return
    fi
    # fallback: bandwidth cap instead of delay (rate in ms arg reused as mbit below)
    :
}
ip netns exec branch_rtr tc qdisc add dev wan1-br root netem delay 15ms 2>/dev/null \
  || ip netns exec branch_rtr tc qdisc add dev wan1-br root tbf rate 2mbit burst 32kbit latency 100ms
ip netns exec branch_rtr tc qdisc add dev wan2-br root netem delay 40ms 2>/dev/null \
  || ip netns exec branch_rtr tc qdisc add dev wan2-br root tbf rate 1mbit burst 32kbit latency 100ms
ip netns exec hq_rtr     tc qdisc add dev wan1-hq root netem delay 15ms 2>/dev/null \
  || ip netns exec hq_rtr     tc qdisc add dev wan1-hq root tbf rate 2mbit burst 32kbit latency 100ms
ip netns exec hq_rtr     tc qdisc add dev wan2-hq root netem delay 40ms 2>/dev/null \
  || ip netns exec hq_rtr     tc qdisc add dev wan2-hq root tbf rate 1mbit burst 32kbit latency 100ms

echo "[*] NOTE: hq_rtr routes back to the branch zones are static via WAN1 only"
echo "    (see docs/LIMITATIONS.md). This is a documented simplification, not a bug."

echo "[*] Topology is up."
echo "    IT zone : it_pc 10.10.1.11, it_srv 10.10.1.12"
echo "    OT zone : ot_plc 10.10.2.21, ot_hmi 10.10.2.22"
echo "    HQ zone : hq_srv 10.10.9.50"
echo "    branch_rtr WAN1=10.0.1.1 WAN2=10.0.2.1 | hq_rtr WAN1=10.0.1.2 WAN2=10.0.2.2"
