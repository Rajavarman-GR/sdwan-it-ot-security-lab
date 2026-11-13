# Sample captured results

These logs were captured from real, working runs of this project (topology
built, attacks launched, detectors running) before this project was handed
over — kept here as a reference for what correct output looks like and as
a fallback if you want text to quote while you capture your own
screenshots.

- `failover_failback.log` — controller.py's full path transition under
  fault-injected WAN1 outage (see docs/LIMITATIONS.md §3): starts on WAN1,
  fails over to WAN2, fails back to WAN1 once the fault is removed.
- `flood_detect_and_block.log` — flood_detector.py detecting and blocking
  attacks/link_flood.py launched from it_pc, in real time.
- `arp_spoof_detect.log` — arp_detector.py catching attacks/arp_spoof.py
  (IP/MAC conflict for the IT gateway address).
- `rogue_gateway_detect.log` — rogue_gateway_detector.py catching
  attacks/rogue_gateway.py (gateway IP claimed by an untrusted MAC).

You should still capture your own run on your VM for the report — these
are provided so you can see the expected shape of the output.
