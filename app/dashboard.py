"""
PyreWall — Web Dashboard
Flask-based visual interface for monitoring and managing the firewall.
"""
import json
from flask import Flask, render_template_string, jsonify, request
from app.firewall import FirewallEngine
from app.simulator import run_simulation
import threading

import socket

def _get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

app = Flask(__name__)
fw = FirewallEngine(local_ip=_get_local_ip())

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PyreWall Dashboard</title>
<style>
:root {
    --bg: #0a0e14; --surface: #131820; --border: #1e2530;
    --text: #d4d8e0; --muted: #6b7280; --accent: #f97316;
    --green: #22c55e; --red: #ef4444; --blue: #3b82f6;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Courier New', monospace; background: var(--bg); color: var(--text); }
.header {
    background: var(--surface); border-bottom: 2px solid var(--accent);
    padding: 16px 24px; display: flex; align-items: center; justify-content: space-between;
}
.header h1 { font-size: 1.3rem; color: var(--accent); }
.header .status { display: flex; gap: 12px; align-items: center; }
.badge { padding: 4px 12px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }
.badge-green { background: rgba(34,197,94,0.15); color: var(--green); border: 1px solid var(--green); }
.badge-red { background: rgba(239,68,68,0.15); color: var(--red); border: 1px solid var(--red); }
.container { max-width: 1200px; margin: 20px auto; padding: 0 20px; }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 20px; }
.stat { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 16px; text-align: center; }
.stat .num { font-size: 2rem; font-weight: bold; color: var(--accent); }
.stat .label { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
.panel { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; margin-bottom: 20px; overflow: hidden; }
.panel-header { padding: 12px 16px; border-bottom: 1px solid var(--border); font-weight: bold; font-size: 0.9rem; display: flex; justify-content: space-between; align-items: center; }
table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
th { text-align: left; padding: 8px 12px; color: var(--muted); text-transform: uppercase; font-size: 0.7rem; letter-spacing: 0.5px; border-bottom: 1px solid var(--border); }
td { padding: 8px 12px; border-bottom: 1px solid var(--border); }
tr:hover td { background: rgba(249,115,22,0.05); }
.allow { color: var(--green); } .block { color: var(--red); }
.btn { padding: 6px 14px; border: 1px solid var(--accent); background: transparent; color: var(--accent); border-radius: 4px; cursor: pointer; font-family: inherit; font-size: 0.8rem; }
.btn:hover { background: var(--accent); color: var(--bg); }
.btn-sm { padding: 3px 8px; font-size: 0.7rem; }
.two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
@media (max-width: 768px) { .two-col { grid-template-columns: 1fr; } }
.form-row { margin-bottom: 10px; }
.form-row label { display: block; font-size: 0.75rem; color: var(--muted); margin-bottom: 4px; }
.form-row input, .form-row select { width: 100%; padding: 6px 10px; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; color: var(--text); font-family: inherit; font-size: 0.85rem; }
</style>
</head>
<body>
<div class="header">
    <h1>🔥 PyreWall Dashboard</h1>
    <div class="status">
        <span id="policyBadge" class="badge badge-green">POLICY: ALLOW</span>
        <span id="liveBadge" class="badge badge-red">LIVE: OFF</span>
        <button class="btn" onclick="startLive()" id="btnLive">🟢 Start Live Capture</button>
        <button class="btn" onclick="stopLive()" id="btnStop" style="display:none">🔴 Stop Capture</button>
        <button class="btn" onclick="runDemo()">▶ Run Demo</button>
        <button class="btn" onclick="loadPreset('basic')">Load Basic Rules</button>
        <button class="btn" onclick="loadPreset('strict')">Load Strict Rules</button>
    </div>
</div>
<div class="container">
    <div class="stats-grid">
        <div class="stat"><div class="num" id="total">0</div><div class="label">Total Packets</div></div>
        <div class="stat"><div class="num" id="allowed" style="color:var(--green)">0</div><div class="label">Allowed</div></div>
        <div class="stat"><div class="num" id="blocked" style="color:var(--red)">0</div><div class="label">Blocked</div></div>
        <div class="stat"><div class="num" id="tcp" style="color:var(--blue)">0</div><div class="label">TCP</div></div>
        <div class="stat"><div class="num" id="udp" style="color:var(--accent)">0</div><div class="label">UDP</div></div>
        <div class="stat"><div class="num" id="rateLimited" style="color:var(--red)">0</div><div class="label">Rate Limited</div></div>
    </div>

    <div class="two-col">
        <div class="panel">
            <div class="panel-header">Active Rules <button class="btn btn-sm" onclick="refreshRules()">Refresh</button></div>
            <table><thead><tr><th>ID</th><th>Action</th><th>Proto</th><th>Dst Port</th><th>Hits</th><th>Desc</th><th></th></tr></thead>
            <tbody id="rulesBody"></tbody></table>
        </div>
        <div class="panel">
            <div class="panel-header">Add Rule</div>
            <div style="padding:12px">
                <div class="form-row"><label>Action</label><select id="rAction"><option value="block">Block</option><option value="allow">Allow</option></select></div>
                <div class="form-row"><label>Protocol</label><select id="rProto"><option value="">Any</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option></select></div>
                <div class="form-row"><label>Source IP</label><input id="rSrcIp" placeholder="Leave blank for any"></div>
                <div class="form-row"><label>Dest Port</label><input id="rDstPort" type="number" placeholder="e.g. 80, 443"></div>
                <div class="form-row"><label>Description</label><input id="rDesc" placeholder="Rule description"></div>
                <button class="btn" onclick="addRule()" style="width:100%;margin-top:8px">Add Rule</button>
            </div>
        </div>
    </div>

    <div class="panel">
        <div class="panel-header">Recent Packets <button class="btn btn-sm" onclick="refreshPackets()">Refresh</button></div>
        <table><thead><tr><th>Time</th><th>Action</th><th>Proto</th><th>Source</th><th>Destination</th><th>Service</th><th>Rule</th></tr></thead>
        <tbody id="packetsBody"></tbody></table>
    </div>

    <div class="panel">
        <div class="panel-header">Top Blocked IPs</div>
        <table><thead><tr><th>IP Address</th><th>Blocked Count</th></tr></thead>
        <tbody id="blockedBody"></tbody></table>
    </div>
</div>

<script>
function refreshStats() {
    fetch('/api/stats').then(r=>r.json()).then(d => {
        document.getElementById('total').textContent = d.total_packets;
        document.getElementById('allowed').textContent = d.allowed;
        document.getElementById('blocked').textContent = d.blocked;
        document.getElementById('tcp').textContent = d.tcp;
        document.getElementById('udp').textContent = d.udp;
        document.getElementById('rateLimited').textContent = d.rate_limited;
    });
}
function refreshRules() {
    fetch('/api/rules').then(r=>r.json()).then(data => {
        const body = document.getElementById('rulesBody');
        body.innerHTML = data.rules.map(r =>
            `<tr><td>${r.rule_id}</td><td class="${r.action}">${r.action.toUpperCase()}</td><td>${r.protocol}</td><td>${r.dst_port}</td><td>${r.hit_count}</td><td>${r.description}</td><td><button class="btn btn-sm" onclick="removeRule(${r.rule_id})">×</button></td></tr>`
        ).join('');
        document.getElementById('policyBadge').textContent = 'POLICY: ' + data.default_policy.toUpperCase();
        document.getElementById('policyBadge').className = 'badge ' + (data.default_policy === 'allow' ? 'badge-green' : 'badge-red');
    });
}
function refreshPackets() {
    fetch('/api/packets?count=30').then(r=>r.json()).then(pkts => {
        document.getElementById('packetsBody').innerHTML = pkts.reverse().map(p =>
            `<tr><td>${(p.timestamp||'').slice(11,19)}</td><td class="${p.action}">${p.action.toUpperCase()}</td><td>${p.protocol}</td><td>${p.src_ip}:${p.src_port||'*'}</td><td>${p.dst_ip}:${p.dst_port||'*'}</td><td>${p.service||'-'}</td><td>${p.rule_id}</td></tr>`
        ).join('');
    });
    fetch('/api/blocked').then(r=>r.json()).then(ips => {
        document.getElementById('blockedBody').innerHTML = ips.map(([ip,c]) =>
            `<tr><td>${ip}</td><td>${c}</td></tr>`
        ).join('') || '<tr><td colspan="2" style="color:var(--muted)">No blocked IPs</td></tr>';
    });
}
function addRule() {
    const data = {
        action: document.getElementById('rAction').value,
        protocol: document.getElementById('rProto').value || null,
        src_ip: document.getElementById('rSrcIp').value || null,
        dst_port: document.getElementById('rDstPort').value ? parseInt(document.getElementById('rDstPort').value) : null,
        description: document.getElementById('rDesc').value,
    };
    fetch('/api/rules', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)})
        .then(() => { refreshRules(); document.getElementById('rDesc').value=''; document.getElementById('rDstPort').value=''; document.getElementById('rSrcIp').value=''; });
}
function removeRule(id) { fetch('/api/rules/'+id, {method:'DELETE'}).then(()=>refreshRules()); }
function runDemo() { fetch('/api/demo', {method:'POST'}).then(()=>{ setTimeout(()=>{ refreshStats(); refreshPackets(); refreshRules(); }, 3000); }); }
function startLive() {
    fetch('/api/live/start', {method:'POST'}).then(r=>r.json()).then(d => {
        if(d.status==='started' || d.status==='already_running') {
            document.getElementById('liveBadge').className='badge badge-green';
            document.getElementById('liveBadge').textContent='LIVE: ON ('+d.local_ip+')';
            document.getElementById('btnLive').style.display='none';
            document.getElementById('btnStop').style.display='inline';
        } else { alert('Error: '+d.message+'. Run with: sudo python run.py --web'); }
    }).catch(()=>alert('Failed. Run with: sudo python run.py --web'));
}
function stopLive() {
    fetch('/api/live/stop', {method:'POST'}).then(()=>{
        document.getElementById('liveBadge').className='badge badge-red';
        document.getElementById('liveBadge').textContent='LIVE: OFF';
        document.getElementById('btnLive').style.display='inline';
        document.getElementById('btnStop').style.display='none';
    });
}
function checkLiveStatus() {
    fetch('/api/status').then(r=>r.json()).then(d => {
        if(d.running) {
            document.getElementById('liveBadge').className='badge badge-green';
            document.getElementById('liveBadge').textContent='LIVE: ON ('+d.local_ip+')';
            document.getElementById('btnLive').style.display='none';
            document.getElementById('btnStop').style.display='inline';
        }
    });
}
function loadPreset(name) { fetch('/api/preset/'+name, {method:'POST'}).then(()=>refreshRules()); }
refreshStats(); refreshRules(); refreshPackets(); checkLiveStatus();
setInterval(()=>{ refreshStats(); refreshPackets(); }, 3000);
</script>
</body>
</html>
"""


@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/stats")
def api_stats():
    return jsonify(fw.get_stats())


@app.route("/api/rules", methods=["GET"])
def api_get_rules():
    return jsonify({"rules": fw.list_rules(), "default_policy": fw.default_action})


@app.route("/api/rules", methods=["POST"])
def api_add_rule():
    data = request.json or {}
    rule = fw.add_rule(
        action=data.get("action", "block"),
        protocol=data.get("protocol"),
        src_ip=data.get("src_ip"),
        dst_ip=data.get("dst_ip"),
        src_port=data.get("src_port"),
        dst_port=data.get("dst_port"),
        description=data.get("description", ""),
    )
    return jsonify(rule.to_dict()), 201


@app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
def api_delete_rule(rule_id):
    fw.remove_rule(rule_id)
    return jsonify({"deleted": True})


@app.route("/api/packets")
def api_packets():
    count = request.args.get("count", 50, type=int)
    return jsonify(fw.get_recent_packets(count))


@app.route("/api/blocked")
def api_blocked():
    return jsonify(fw.get_top_blocked())


@app.route("/api/demo", methods=["POST"])
def api_demo():
    def _run():
        run_simulation(fw)
    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "running"})


@app.route("/api/live/start", methods=["POST"])
def api_live_start():
    """Start real packet capture (requires root/sudo)."""
    if fw.is_running:
        return jsonify({"status": "already_running"})
    try:
        fw.start_async()
        return jsonify({"status": "started", "local_ip": fw.local_ip})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/live/stop", methods=["POST"])
def api_live_stop():
    """Stop real packet capture."""
    fw.stop()
    return jsonify({"status": "stopped"})


@app.route("/api/status")
def api_status():
    return jsonify({"running": fw.is_running, "local_ip": fw.local_ip})


@app.route("/api/preset/<name>", methods=["POST"])
def api_preset(name):
    fw.rules.clear()
    if name == "strict":
        fw.load_preset_strict()
    else:
        fw.load_preset_basic()
    return jsonify({"loaded": name})


def run_dashboard(host="127.0.0.1", port=5000):
    """Start the web dashboard."""
    print(f"\n  🔥 PyreWall Dashboard running at http://{host}:{port}")
    print(f"  Open in your browser to manage the firewall.\n")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    run_dashboard()
