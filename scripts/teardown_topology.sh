#!/bin/bash
# teardown_topology.sh — removes everything setup_topology.sh created.
set +e

for ns in it_pc it_srv ot_plc ot_hmi branch_rtr hq_rtr hq_srv; do
    ip netns del "$ns" 2>/dev/null
done

for v in veth-itpc-h veth-itsrv-h veth-otplc-h veth-othmi-h \
         veth-br-it-h veth-br-ot-h veth-hqrtr-h veth-hqsrv-h \
         wan1-br wan2-br; do
    ip link del "$v" 2>/dev/null
done

for br in br-it br-ot br-hq; do
    ip link del "$br" 2>/dev/null
done

echo "[*] Topology removed."
