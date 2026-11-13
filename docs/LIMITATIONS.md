# Known limitations and design notes

This project was built and test-run inside a minimal sandboxed container to
verify every script before handing it over. Two things are worth knowing
before you run it on your own VM, plus the simplifications made on purpose
to keep this an intermediate-scope project.

## 1. Interface naming

Every virtual interface in `setup_topology.sh` uses project-specific names
(`it0`, `ot0`, `itlink`, `wan1-br`, ...) instead of generic names like
`eth0`. On some hosts (cloud VMs, some containers) `eth0` is reserved for
the machine's real network interface, and creating another device with
that name inside a namespace can rename or disrupt the host's own network
connectivity. Keep this naming scheme if you extend the script.

## 2. WAN shaping: netem vs tbf

`setup_topology.sh` tries `tc ... netem delay` first (adds realistic
latency/jitter) and automatically falls back to `tc ... tbf` (a bandwidth
cap) if the kernel doesn't have `sch_netem` built in. Some minimal/hardened
kernels (certain microVMs and stripped-down containers) don't ship
`sch_netem`; almost every normal Ubuntu Desktop/Server kernel does. Either
way, WAN1 ends up the "better" path (lower delay or higher bandwidth) so it
is preferred under normal conditions, and a flood can still push it into
real, measurable congestion.

Check which one you're using:
```
ip netns exec branch_rtr tc qdisc show dev wan1-br
```

## 3. Validating the controller's failover independently of the flood

The intended end-to-end story is: `attacks/link_flood.py` saturates WAN1 →
`controller.py` observes rising ping loss → it fails over to WAN2. This
works, but how much real throughput `link_flood.py` can push depends on the
CPU available to run Python/Scapy — on a constrained host, a Python-based
flooder may not sustain enough packets/sec to saturate even a small `tbf`
cap for very long, especially once `flood_detector.py` blocks the attacker
within a couple of seconds (which is itself a good result — see below).

To test `controller.py`'s failover/fail-back logic on its own, independent
of how fast the flood generator runs, inject a fault directly:
```
# Simulate a WAN1 outage:
ip netns exec branch_rtr iptables -I OUTPUT 1 -p icmp -d 10.0.1.2 -j DROP
# ... watch logs/state.json flip to WAN2 ...
# Then restore it:
ip netns exec branch_rtr iptables -D OUTPUT -p icmp -d 10.0.1.2 -j DROP
# ... watch it fail back to WAN1 ...
```
This is a standard resilience-testing technique (fault injection) and is
worth describing in the report as a controlled validation step, separate
from the attack demo.

### Why the flood might get blocked before you see a failover

If `flood_detector.py` is running at the same time as the flood, it will
usually detect and block the attacking source (via iptables) within one or
two detection windows (≈2–4 seconds) — often before WAN1 has been
congested long enough for `controller.py`'s slower ping-based health check
to notice and fail over. That's not a bug: it demonstrates that **fast
detection and blocking at the SOC layer can prevent an attack from ever
needing the slower network-resilience layer to kick in.** For the report,
it's worth running both scenarios and comparing them:
- flood + `controller.py` alone → shows failover under sustained
  degradation.
- flood + `controller.py` + `flood_detector.py` together → shows the
  attacker blocked quickly, often before failover is needed.

## 4. Static HQ-side routing

`hq_rtr`'s routes back to the IT/OT zones are static, via WAN1 only. In a
real SD-WAN both ends run dynamic path selection. Here, a flood from the
IT/OT zone congests branch_rtr's *outbound* path (which the controller does
react to); the return path from `hq_rtr` is not automatically re-routed.
This is a deliberate scope cut to keep the project at an intermediate
level — call it out as "future work" in the conclusion (e.g. "symmetric,
dynamic routing on both edges").

## 5. Attack realism vs. safety

All three attacks (link flooding, ARP spoofing, rogue gateway) run only
inside the private, isolated namespaces created by `setup_topology.sh` —
they never touch a real network, a real Wi-Fi/Ethernet segment, or any
host outside this lab. Do not point `link_flood.py`, `arp_spoof.py`, or
`rogue_gateway.py` at an interface or IP outside this lab topology.
