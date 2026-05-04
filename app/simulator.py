"""
PyreWall — Traffic Simulator
Generates synthetic packets to demonstrate firewall logic WITHOUT root privileges.
Perfect for viva demos — no network access needed.
"""
import time
import random
from datetime import datetime


# Simulated traffic scenarios
NORMAL_TRAFFIC = [
    {"src_ip": "192.168.1.100", "dst_ip": "142.250.195.46", "protocol": "TCP", "src_port": 52341, "dst_port": 443, "service": "HTTPS", "direction": "outbound", "size": 1280},
    {"src_ip": "192.168.1.100", "dst_ip": "142.250.195.46", "protocol": "TCP", "src_port": 52342, "dst_port": 80, "service": "HTTP", "direction": "outbound", "size": 540},
    {"src_ip": "192.168.1.100", "dst_ip": "8.8.8.8", "protocol": "UDP", "src_port": 49152, "dst_port": 53, "service": "DNS", "direction": "outbound", "size": 72},
    {"src_ip": "8.8.8.8", "dst_ip": "192.168.1.100", "protocol": "UDP", "src_port": 53, "dst_port": 49152, "service": "DNS", "direction": "inbound", "size": 128},
    {"src_ip": "192.168.1.100", "dst_ip": "151.101.1.69", "protocol": "TCP", "src_port": 52400, "dst_port": 443, "service": "HTTPS", "direction": "outbound", "size": 920},
    {"src_ip": "192.168.1.100", "dst_ip": "192.168.1.1", "protocol": "ICMP", "src_port": None, "dst_port": None, "service": "Ping", "direction": "outbound", "size": 64},
]

SUSPICIOUS_TRAFFIC = [
    {"src_ip": "10.0.0.55", "dst_ip": "192.168.1.100", "protocol": "TCP", "src_port": 44123, "dst_port": 22, "service": "SSH", "direction": "inbound", "size": 60, "label": "SSH brute force attempt"},
    {"src_ip": "10.0.0.55", "dst_ip": "192.168.1.100", "protocol": "TCP", "src_port": 44124, "dst_port": 23, "service": "Telnet", "direction": "inbound", "size": 60, "label": "Telnet connection attempt"},
    {"src_ip": "10.0.0.55", "dst_ip": "192.168.1.100", "protocol": "TCP", "src_port": 44125, "dst_port": 3389, "service": "RDP", "direction": "inbound", "size": 60, "label": "RDP scan"},
    {"src_ip": "10.0.0.55", "dst_ip": "192.168.1.100", "protocol": "TCP", "src_port": 44126, "dst_port": 445, "service": "SMB", "direction": "inbound", "size": 60, "label": "SMB scan (WannaCry vector)"},
    {"src_ip": "10.0.0.55", "dst_ip": "192.168.1.100", "protocol": "TCP", "src_port": 44127, "dst_port": 135, "service": "RPC", "direction": "inbound", "size": 60, "label": "RPC exploitation attempt"},
    {"src_ip": "10.0.0.55", "dst_ip": "192.168.1.100", "protocol": "TCP", "src_port": 44128, "dst_port": 21, "service": "FTP", "direction": "inbound", "size": 60, "label": "FTP connection attempt"},
]

PORT_SCAN = [
    {"src_ip": "203.0.113.42", "dst_ip": "192.168.1.100", "protocol": "TCP", "src_port": 55000 + i, "dst_port": port, "service": "Scan", "direction": "inbound", "size": 44}
    for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 993, 1433, 3306, 3389, 5432, 5900, 8080])
]


def run_simulation(fw):
    """Run a complete firewall simulation with multiple attack scenarios."""

    print("\n  ╔══════════════════════════════════════════════════╗")
    print("  ║         🔥 PyreWall — Demo/Simulation Mode       ║")
    print("  ║    No root required — synthetic traffic only     ║")
    print("  ╚══════════════════════════════════════════════════╝\n")

    if not fw.rules:
        print("  ⚠️  No rules loaded. Loading basic preset for demo...\n")
        fw.load_preset_basic()

    fw.stats["start_time"] = datetime.now().isoformat()

    # Phase 1: Normal traffic
    print("  ── Phase 1: Normal Traffic ──")
    print("  Simulating regular web browsing and DNS queries...\n")
    for pkt in NORMAL_TRAFFIC:
        _process_simulated(fw, pkt)
        time.sleep(0.15)

    # Phase 2: Suspicious traffic
    print("\n  ── Phase 2: Suspicious Inbound Traffic ──")
    print("  Simulating external attack attempts...\n")
    for pkt in SUSPICIOUS_TRAFFIC:
        label = pkt.pop("label", "")
        _process_simulated(fw, pkt, extra_info=label)
        time.sleep(0.2)

    # Phase 3: Port scan
    print("\n  ── Phase 3: Port Scan Detection ──")
    print(f"  Simulating port scan from 203.0.113.42 (18 ports)...\n")
    for pkt in PORT_SCAN:
        _process_simulated(fw, pkt)
        time.sleep(0.08)

    # Summary
    stats = fw.get_stats()
    print("\n  ═══════════════════════════════════════")
    print("  ── Simulation Summary ──")
    print(f"  Total packets:    {stats['total_packets']}")
    print(f"  Allowed:          {stats['allowed']} ✅")
    print(f"  Blocked:          {stats['blocked']} ❌")
    print(f"  Rate-limited:     {stats['rate_limited']} 🚫")
    print(f"  TCP: {stats['tcp']}  UDP: {stats['udp']}  ICMP: {stats['icmp']}")

    top_blocked = fw.get_top_blocked(5)
    if top_blocked:
        print("\n  ── Top Blocked IPs ──")
        for ip, count in top_blocked:
            print(f"    {ip:<20} {count} packets blocked")

    print("\n  ═══════════════════════════════════════")
    print("  Demo complete. Type 'packets' to view packet log, 'rules' to see rule hits.\n")


def _process_simulated(fw, pkt_info, extra_info=""):
    """Process a single simulated packet through the firewall."""
    pkt_info["timestamp"] = datetime.now().isoformat()
    if "size" not in pkt_info:
        pkt_info["size"] = random.randint(40, 1500)

    action, matched_rule = fw.evaluate_packet(pkt_info)

    # Update stats
    fw.stats["total_packets"] += 1
    if action == "allow":
        fw.stats["allowed"] += 1
    else:
        fw.stats["blocked"] += 1
        if pkt_info.get("src_ip"):
            fw.blocked_ips[pkt_info["src_ip"]] += 1

    proto = pkt_info.get("protocol", "OTHER").lower()
    if proto in fw.stats:
        fw.stats[proto] += 1
    else:
        fw.stats["other"] += 1

    # Store in recent packets
    log_entry = {
        **pkt_info,
        "action": action,
        "rule_id": matched_rule.rule_id if matched_rule else "default",
    }
    fw.recent_packets.append(log_entry)

    # Display
    icon = "✅ ALLOW" if action == "allow" else "❌ BLOCK"
    src = f"{pkt_info.get('src_ip', '?')}:{pkt_info.get('src_port', '*')}"
    dst = f"{pkt_info.get('dst_ip', '?')}:{pkt_info.get('dst_port', '*')}"
    rule_info = f"Rule #{matched_rule.rule_id}" if matched_rule else f"Default ({fw.default_action})"
    extra = f" — {extra_info}" if extra_info else ""

    print(f"    {icon}  {pkt_info['protocol']:<5} {src:<25} -> {dst:<25} [{rule_info}]{extra}")
