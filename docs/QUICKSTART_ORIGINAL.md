# Simulation and Detection of Network Attacks in an SD-WAN with IT/OT Segmentation

An intermediate-level security project: a simulated two-path SD-WAN
(WAN1 primary, WAN2 backup) connecting segmented IT and OT zones to a
head office, with three attacks (link flooding, ARP spoofing, rogue
gateway) and a matching detector for each, plus a path-health controller
and a live status dashboard.

## Architecture

```
IT zone (10.10.1.0/24)              OT zone (10.10.2.0/24)
  it_pc, it_srv                       ot_plc, ot_hmi
        \                                   /
       (br-it)                          (br-ot)
            \                           /
             [ branch_rtr ] ---------- (IT<->OT direct traffic DROPPED)
              |itlink  |otlink
              |WAN1    |WAN2
          10.0.1.0/30  10.0.2.0/30
              |            |
             [ hq_rtr ]----+
                  |
               (br-hq)
                  |
               hq_srv (10.10.9.0/24)
```

- `branch_rtr` is the SD-WAN edge: it enforces IT/OT segmentation
  (`iptables` drops any `itlink<->otlink` traffic) and chooses between
  WAN1 and WAN2 for the route to HQ.
- `hq_rtr` terminates both WAN links and forwards into the HQ zone.
- WAN1 is the preferred path (lower delay / higher bandwidth); WAN2 is
  the backup.

See `docs/LIMITATIONS.md` for the handful of deliberate scope cuts that
keep this at an intermediate level, and for how WAN shaping falls back
from `netem` to `tbf` depending on the kernel.

## Requirements

- A Linux VM (tested design target: Ubuntu 22.04/24.04), run as **root**.
- `apt install iproute2 iptables python3-pip`
- `pip install scapy flask --break-system-packages` (or inside a venv)

## 1. Build the topology

```
sudo bash scripts/setup_topology.sh
```
Prints the topology summary and addresses when done. Tear down with:
```
sudo bash scripts/teardown_topology.sh
```

## 2. Sanity-check it

```
sudo ip netns exec it_pc ping -c3 10.10.9.50      # IT -> HQ: should work
sudo ip netns exec ot_plc ping -c3 10.10.9.50     # OT -> HQ: should work
sudo ip netns exec it_pc ping -c3 10.10.2.21       # IT -> OT: should be blocked
```

## 3. Run the controller (path health + failover)

```
sudo ip netns exec branch_rtr python3 scripts/controller.py
```
Leave it running in one terminal. It logs every path transition to
`logs/alerts.log` / `logs/alerts.jsonl` and keeps current state in
`logs/state.json`.

## 4. Run the three attack/detection scenarios

Each attack has its own detector. Run the detector first (it's usually
long-running), then the attack from a second terminal, or use the
provided wrapper:

```
sudo bash scripts/run_demo.sh flood     # attacks/link_flood.py + detection/flood_detector.py
sudo bash scripts/run_demo.sh arp       # attacks/arp_spoof.py + detection/arp_detector.py
sudo bash scripts/run_demo.sh rogue     # attacks/rogue_gateway.py + detection/rogue_gateway_detector.py
sudo bash scripts/run_demo.sh all       # all three, one after another
```

Or run any script manually — every attack/detector takes `--help` for its
arguments; the docstring at the top of each file also shows the exact
`ip netns exec ...` invocation it expects.

| # | Attack | Attacker | Victim/target | Detector | Response |
|---|--------|----------|----------------|----------|----------|
| 1 | Link flooding | `it_pc` | WAN1 toward `hq_srv` | `flood_detector.py` (packet-rate, on `branch_rtr`) | Blocks the source IP with `iptables` |
| 2 | ARP spoofing | `it_srv` | `it_pc`'s view of the gateway | `arp_detector.py` (on `br-it`) | Alerts on IP/MAC conflict |
| 3 | Rogue gateway | `ot_hmi` | OT gateway IP | `rogue_gateway_detector.py` (on `br-ot`) | Alerts when a non-trusted MAC claims the gateway IP |

## 5. Dashboard

```
python3 dashboard/app.py
```
Open `http://<vm-ip>:5000`. Auto-refreshes every 3s, shows the active WAN
path and a live alert table. Also exposes `/api/state` and `/api/alerts`
as JSON if you'd rather screenshot raw output for the report.

## Project layout

```
scripts/
  setup_topology.sh       topology build (namespaces, bridges, routing, segmentation)
  teardown_topology.sh    tears it all down
  controller.py           WAN1/WAN2 health-check + failover
  alert_logger.py         shared logging used by controller + all detectors
  run_demo.sh             convenience wrapper for the three scenarios
attacks/
  link_flood.py
  arp_spoof.py
  rogue_gateway.py
detection/
  flood_detector.py
  arp_detector.py
  rogue_gateway_detector.py
dashboard/
  app.py                  Flask live-status dashboard
logs/                     alerts.log, alerts.jsonl, state.json (created at runtime)
docs/
  LIMITATIONS.md           known limitations + how to validate failover independently
```

## Suggested report structure (matches your existing report format)

1. Company/internship overview — unchanged from your existing AmZetta chapter.
2. Project overview — this README's architecture section, redrawn as a
   figure.
3. Design — the table above, plus the IT/OT segmentation rule set
   (`iptables` rules printed by `setup_topology.sh`).
4. Implementation — one subsection per attack/detector pair, with the
   relevant script's docstring as the method description.
5. Results — screenshots of: (a) segmentation test, (b) each attack's
   console output, (c) the matching alert(s) in `logs/alerts.log` or the
   dashboard, (d) the controller failover/fail-back transition (see
   `docs/LIMITATIONS.md §3` for how to demonstrate this cleanly).
6. Conclusion / future work — dynamic HQ-side routing, encrypted WAN
   tunnels, extending `flood_detector.py`'s response to also notify
   `controller.py` directly, sending alerts to Wazuh instead of a flat
   file.
