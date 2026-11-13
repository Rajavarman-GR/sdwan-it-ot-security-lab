#!/usr/bin/env python3
"""
dashboard/app.py — simple Flask dashboard for the project.

Shows the active WAN path (from controller.py) and a live-updating table
of alerts (from every attack detector). Run this on the HOST, not inside
a namespace — it only reads the shared log files under ../logs/.

Run as:  python3 dashboard/app.py
Then open http://127.0.0.1:5000 in a browser.
"""
import os
import sys

from flask import Flask, jsonify, render_template_string

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from alert_logger import read_alerts, get_state  # noqa: E402

app = Flask(__name__)

PAGE = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>SD-WAN Security Dashboard</title>
<meta http-equiv="refresh" content="3">
<style>
  body { font-family: system-ui, sans-serif; margin: 2rem; background: #0b1020; color: #e6e6e6; }
  h1 { font-size: 1.3rem; }
  .path { font-size: 1.1rem; margin-bottom: 1rem; }
  .ok { color: #4ade80; } .warn { color: #fbbf24; } .bad { color: #f87171; }
  table { border-collapse: collapse; width: 100%; }
  th, td { border-bottom: 1px solid #2a3350; padding: 0.4rem 0.6rem; text-align: left; font-size: 0.85rem; }
  th { color: #94a3b8; }
  tr.critical { background: rgba(248,113,113,0.12); }
  tr.warning  { background: rgba(251,191,36,0.10); }
</style>
</head>
<body>
  <h1>Secure SD-WAN for OT Environments — Live Status</h1>
  <div class="path">
    Active WAN path:
    <b class="{{ 'ok' if state.get('active_path')=='WAN1' else 'warn' }}">
      {{ state.get('active_path', 'unknown') }}
    </b>
    &nbsp;|&nbsp; WAN1 loss: {{ state.get('wan1_loss_pct', 'n/a') }}%
    &nbsp;|&nbsp; last update: {{ state.get('updated', 'n/a') }}
  </div>
  <table>
    <tr><th>Time</th><th>Source</th><th>Severity</th><th>Message</th></tr>
    {% for a in alerts|reverse %}
    <tr class="{{ a.severity }}">
      <td>{{ a.timestamp }}</td>
      <td>{{ a.source }}</td>
      <td class="{{ 'bad' if a.severity=='critical' else ('warn' if a.severity=='warning' else 'ok') }}">
        {{ a.severity }}
      </td>
      <td>{{ a.message }}</td>
    </tr>
    {% endfor %}
  </table>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(PAGE, state=get_state(), alerts=read_alerts())


@app.route("/api/alerts")
def api_alerts():
    return jsonify(read_alerts())


@app.route("/api/state")
def api_state():
    return jsonify(get_state())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
