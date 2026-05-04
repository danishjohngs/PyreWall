"""
PyreWall — Command Line Interface
Interactive terminal-based firewall management.
"""
import sys
import signal
import socket
from app.firewall import FirewallEngine


def get_local_ip():
    """Get the local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def print_banner():
    print("""
╔══════════════════════════════════════════════════╗
║          🔥 PyreWall — Personal Firewall         ║
║        Network Packet Filtering & Monitoring     ║
╚══════════════════════════════════════════════════╝
    """)


def print_help():
    print("""
Commands:
  start             Start packet capture (requires root/admin)
  stop              Stop packet capture
  status            Show firewall status and statistics

  rules             List all active rules
  add               Add a new rule (interactive)
  remove <id>       Remove a rule by ID
  policy <action>   Set default policy (allow/block)

  preset basic      Load basic security rules
  preset strict     Load strict rules (whitelist mode)

  save [file]       Save rules to JSON file
  load [file]       Load rules from JSON file

  packets [n]       Show last n captured packets (default: 20)
  blocked           Show top blocked IPs

  demo              Run in demo/simulation mode (no root needed)
  help              Show this help
  quit              Exit
    """)


def add_rule_interactive(fw):
    """Interactive rule addition."""
    print("\n── Add Firewall Rule ──")

    action = input("  Action (allow/block) [block]: ").strip().lower() or "block"
    if action not in ("allow", "block"):
        print("  Invalid action.")
        return

    direction = input("  Direction (inbound/outbound/both) [both]: ").strip().lower() or "both"
    protocol = input("  Protocol (tcp/udp/icmp/any) [any]: ").strip().lower() or None
    if protocol == "any":
        protocol = None

    src_ip = input("  Source IP (or blank for any): ").strip() or None
    dst_ip = input("  Destination IP (or blank for any): ").strip() or None

    src_port = input("  Source port (or blank for any): ").strip()
    src_port = int(src_port) if src_port else None

    dst_port = input("  Destination port (or blank for any): ").strip()
    dst_port = int(dst_port) if dst_port else None

    desc = input("  Description: ").strip()

    rule = fw.add_rule(
        action=action, direction=direction, protocol=protocol,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port, description=desc,
    )
    print(f"  ✅ Rule #{rule.rule_id} added: {action.upper()} {desc}")


def print_rules(fw):
    """Display all rules in a table."""
    rules = fw.list_rules()
    if not rules:
        print("  No rules configured. Use 'preset basic' or 'add' to create rules.")
        return

    print(f"\n  Default policy: {fw.default_action.upper()}")
    print(f"  {'ID':<5} {'Action':<8} {'Dir':<10} {'Proto':<7} {'Src IP':<18} {'Dst IP':<18} {'DPort':<7} {'Hits':<6} Description")
    print("  " + "─" * 105)
    for r in rules:
        print(f"  {r['rule_id']:<5} {r['action']:<8} {r['direction']:<10} {r['protocol']:<7} "
              f"{r['src_ip']:<18} {r['dst_ip']:<18} {str(r['dst_port']):<7} {r['hit_count']:<6} {r['description']}")


def print_stats(fw):
    """Display firewall statistics."""
    s = fw.get_stats()
    print(f"""
  ── Firewall Status ──
  Running:       {'YES 🟢' if fw.is_running else 'NO 🔴'}
  Default:       {fw.default_action.upper()}
  Since:         {s['start_time'] or 'Not started'}

  ── Packet Statistics ──
  Total:         {s['total_packets']}
  Allowed:       {s['allowed']}
  Blocked:       {s['blocked']}
  Rate-limited:  {s['rate_limited']}

  ── Protocol Breakdown ──
  TCP:           {s['tcp']}
  UDP:           {s['udp']}
  ICMP:          {s['icmp']}
  Other:         {s['other']}
    """)


def print_packets(fw, count=20):
    """Display recent packets."""
    packets = fw.get_recent_packets(count)
    if not packets:
        print("  No packets captured yet.")
        return

    print(f"\n  Last {len(packets)} packets:")
    print(f"  {'Time':<12} {'Action':<8} {'Proto':<6} {'Source':<22} {'Destination':<22} {'Service':<10} {'Rule'}")
    print("  " + "─" * 95)
    for p in packets:
        src = f"{p.get('src_ip', '?')}:{p.get('src_port', '?')}"
        dst = f"{p.get('dst_ip', '?')}:{p.get('dst_port', '?')}"
        time_short = p.get("timestamp", "?")[11:19]
        action_icon = "✅" if p["action"] == "allow" else "❌"
        print(f"  {time_short:<12} {action_icon} {p['action']:<5} {p['protocol']:<6} "
              f"{src:<22} {dst:<22} {p.get('service', '?'):<10} {p.get('rule_id', '?')}")


def print_blocked(fw):
    """Show top blocked IPs."""
    top = fw.get_top_blocked()
    if not top:
        print("  No blocked IPs yet.")
        return

    print("\n  ── Top Blocked IPs ──")
    print(f"  {'IP Address':<20} {'Blocked Count'}")
    print("  " + "─" * 35)
    for ip, count in top:
        print(f"  {ip:<20} {count}")


def run_demo(fw):
    """
    Simulate packet processing without root privileges.
    Generates synthetic packets to demonstrate the firewall logic.
    """
    from app.simulator import run_simulation
    run_simulation(fw)


def main():
    print_banner()

    local_ip = get_local_ip()
    print(f"  Local IP: {local_ip}")

    fw = FirewallEngine(local_ip=local_ip)

    # Handle Ctrl+C
    def signal_handler(sig, frame):
        if fw.is_running:
            fw.stop()
            print("\n  Firewall stopped.")
        print("\n  Goodbye!")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    print_help()

    while True:
        try:
            cmd = input("\n🔥 pyrewall> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  Goodbye!")
            break

        if not cmd:
            continue

        parts = cmd.split()
        action = parts[0]

        if action == "quit" or action == "exit":
            if fw.is_running:
                fw.stop()
            print("  Goodbye!")
            break

        elif action == "help":
            print_help()

        elif action == "start":
            if fw.is_running:
                print("  Already running.")
            else:
                print("  Starting packet capture (Ctrl+C to stop)...")
                print("  Note: Requires root/sudo privileges.")
                try:
                    fw.start_async()
                    print("  ✅ Firewall started in background.")
                except Exception as e:
                    print(f"  ❌ Error: {e}")

        elif action == "stop":
            fw.stop()
            print("  ✅ Firewall stopped.")

        elif action == "status":
            print_stats(fw)

        elif action == "rules":
            print_rules(fw)

        elif action == "add":
            add_rule_interactive(fw)

        elif action == "remove":
            if len(parts) < 2:
                print("  Usage: remove <rule_id>")
            else:
                try:
                    fw.remove_rule(int(parts[1]))
                    print(f"  ✅ Rule #{parts[1]} removed.")
                except ValueError:
                    print("  Invalid rule ID.")

        elif action == "policy":
            if len(parts) < 2 or parts[1] not in ("allow", "block"):
                print("  Usage: policy allow|block")
            else:
                fw.set_default_policy(parts[1])
                print(f"  ✅ Default policy set to {parts[1].upper()}")

        elif action == "preset":
            if len(parts) < 2:
                print("  Usage: preset basic|strict")
            elif parts[1] == "basic":
                fw.load_preset_basic()
                print("  ✅ Basic ruleset loaded.")
                print_rules(fw)
            elif parts[1] == "strict":
                fw.load_preset_strict()
                print("  ✅ Strict ruleset loaded (default: BLOCK).")
                print_rules(fw)
            else:
                print("  Unknown preset. Use 'basic' or 'strict'.")

        elif action == "save":
            filepath = parts[1] if len(parts) > 1 else "rules.json"
            fw.save_rules(filepath)
            print(f"  ✅ Rules saved to {filepath}")

        elif action == "load":
            filepath = parts[1] if len(parts) > 1 else "rules.json"
            fw.load_rules(filepath)
            print(f"  ✅ Rules loaded from {filepath}")
            print_rules(fw)

        elif action == "packets":
            count = int(parts[1]) if len(parts) > 1 else 20
            print_packets(fw, count)

        elif action == "blocked":
            print_blocked(fw)

        elif action == "demo":
            run_demo(fw)

        else:
            print(f"  Unknown command: {action}. Type 'help' for commands.")


if __name__ == "__main__":
    main()
