"""
PyreWall — Core Firewall Engine
Captures network packets using Scapy and applies user-defined filtering rules.
Supports: IP blocking, port blocking, protocol filtering, rate limiting, and logging.
"""
import time
import json
import threading
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except (ImportError, KeyError, OSError):
    SCAPY_AVAILABLE = False
    # Define dummy classes for environments where Scapy fails to load
    class _DummyLayer:
        pass
    IP = TCP = UDP = ICMP = Raw = _DummyLayer
    sniff = None

from app.logger import SecurityLogger


class FirewallRule:
    """Represents a single firewall rule."""

    def __init__(self, rule_id, action, direction="both", protocol=None,
                 src_ip=None, dst_ip=None, src_port=None, dst_port=None,
                 description=""):
        self.rule_id = rule_id
        self.action = action          # "allow" or "block"
        self.direction = direction    # "inbound", "outbound", "both"
        self.protocol = protocol      # "tcp", "udp", "icmp", or None (all)
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.description = description
        self.hit_count = 0
        self.created_at = datetime.now().isoformat()

    def matches(self, packet_info):
        """Check if a packet matches this rule."""
        # Protocol check
        if self.protocol and packet_info.get("protocol", "").lower() != self.protocol.lower():
            return False

        # Source IP check
        if self.src_ip and packet_info.get("src_ip") != self.src_ip:
            return False

        # Destination IP check
        if self.dst_ip and packet_info.get("dst_ip") != self.dst_ip:
            return False

        # Source port check
        if self.src_port and packet_info.get("src_port") != self.src_port:
            return False

        # Destination port check
        if self.dst_port and packet_info.get("dst_port") != self.dst_port:
            return False

        # Direction check
        if self.direction == "inbound" and packet_info.get("direction") == "outbound":
            return False
        if self.direction == "outbound" and packet_info.get("direction") == "inbound":
            return False

        return True

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "action": self.action,
            "direction": self.direction,
            "protocol": self.protocol or "any",
            "src_ip": self.src_ip or "any",
            "dst_ip": self.dst_ip or "any",
            "src_port": self.src_port or "any",
            "dst_port": self.dst_port or "any",
            "description": self.description,
            "hit_count": self.hit_count,
            "created_at": self.created_at,
        }


class RateLimiter:
    """Tracks connection rates per IP for DDoS / port scan detection."""

    def __init__(self, max_connections=50, window_seconds=10):
        self.max_connections = max_connections
        self.window = window_seconds
        self.connections = defaultdict(list)
        self.lock = threading.Lock()

    def check(self, ip):
        """Returns True if IP is within rate limit, False if exceeded."""
        now = time.time()
        with self.lock:
            # Clean old entries
            self.connections[ip] = [
                t for t in self.connections[ip] if now - t < self.window
            ]
            self.connections[ip].append(now)
            return len(self.connections[ip]) <= self.max_connections

    def get_rate(self, ip):
        """Get current connection rate for an IP."""
        now = time.time()
        with self.lock:
            self.connections[ip] = [
                t for t in self.connections[ip] if now - t < self.window
            ]
            return len(self.connections[ip])


class PacketAnalyzer:
    """Extracts information from captured packets."""

    # Well-known ports for display
    PORT_NAMES = {
        20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
        143: "IMAP", 443: "HTTPS", 993: "IMAPS", 995: "POP3S",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    }

    @staticmethod
    def extract_info(packet, local_ip=None):
        """Extract relevant info from a Scapy packet."""
        info = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "protocol": "OTHER",
            "size": len(packet),
            "direction": "unknown",
            "flags": None,
            "service": "Unknown",
        }

        if IP in packet:
            info["src_ip"] = packet[IP].src
            info["dst_ip"] = packet[IP].dst

            # Determine direction
            if local_ip:
                if packet[IP].dst == local_ip:
                    info["direction"] = "inbound"
                elif packet[IP].src == local_ip:
                    info["direction"] = "outbound"

        if TCP in packet:
            info["protocol"] = "TCP"
            info["src_port"] = packet[TCP].sport
            info["dst_port"] = packet[TCP].dport
            info["flags"] = str(packet[TCP].flags)
            info["service"] = PacketAnalyzer.PORT_NAMES.get(
                packet[TCP].dport,
                PacketAnalyzer.PORT_NAMES.get(packet[TCP].sport, "Unknown")
            )
        elif UDP in packet:
            info["protocol"] = "UDP"
            info["src_port"] = packet[UDP].sport
            info["dst_port"] = packet[UDP].dport
            info["service"] = PacketAnalyzer.PORT_NAMES.get(
                packet[UDP].dport,
                PacketAnalyzer.PORT_NAMES.get(packet[UDP].sport, "Unknown")
            )
        elif ICMP in packet:
            info["protocol"] = "ICMP"
            info["service"] = "Ping"

        return info


class FirewallEngine:
    """
    Main firewall engine.
    Captures packets, applies rules, logs decisions, and tracks statistics.
    """

    def __init__(self, local_ip="127.0.0.1", interface=None):
        self.local_ip = local_ip
        self.interface = interface
        self.rules = []
        self.is_running = False
        self.default_action = "allow"  # Default policy: allow all
        self.logger = SecurityLogger()
        self.rate_limiter = RateLimiter(max_connections=200, window_seconds=10)
        self.analyzer = PacketAnalyzer()

        # Statistics
        self.stats = {
            "total_packets": 0,
            "allowed": 0,
            "blocked": 0,
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "other": 0,
            "rate_limited": 0,
            "start_time": None,
        }
        self.stats_lock = threading.Lock()

        # Packet log (recent packets for dashboard)
        self.recent_packets = []
        self.max_recent = 200
        self.packets_lock = threading.Lock()

        # Blocked IPs tracking
        self.blocked_ips = defaultdict(int)

        self._next_rule_id = 1

    # ── Rule Management ─────────────────────────────────────────────

    def add_rule(self, action, direction="both", protocol=None,
                 src_ip=None, dst_ip=None, src_port=None, dst_port=None,
                 description=""):
        """Add a firewall rule. Rules are evaluated top-down (first match wins)."""
        rule = FirewallRule(
            rule_id=self._next_rule_id,
            action=action,
            direction=direction,
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            description=description,
        )
        self.rules.append(rule)
        self._next_rule_id += 1
        self.logger.log_event("RULE_ADDED", f"Rule #{rule.rule_id}: {action} {description}")
        return rule

    def remove_rule(self, rule_id):
        """Remove a rule by ID."""
        self.rules = [r for r in self.rules if r.rule_id != rule_id]
        self.logger.log_event("RULE_REMOVED", f"Rule #{rule_id} removed")

    def list_rules(self):
        """Return all rules as dicts."""
        return [r.to_dict() for r in self.rules]

    def set_default_policy(self, action):
        """Set default policy: 'allow' or 'block'."""
        if action in ("allow", "block"):
            self.default_action = action
            self.logger.log_event("POLICY_CHANGED", f"Default policy set to {action}")

    # ── Packet Processing ───────────────────────────────────────────

    def evaluate_packet(self, packet_info):
        """
        Evaluate a packet against all rules (first match wins).
        Returns: ("allow" or "block", matched_rule or None)
        """
        # Rate limiting check first
        src_ip = packet_info.get("src_ip")
        if src_ip and not self.rate_limiter.check(src_ip):
            with self.stats_lock:
                self.stats["rate_limited"] += 1
            return "block", None

        # Evaluate rules top-down
        for rule in self.rules:
            if rule.matches(packet_info):
                rule.hit_count += 1
                return rule.action, rule

        # Default policy
        return self.default_action, None

    def _process_packet(self, packet):
        """Callback for each captured packet."""
        if not packet.haslayer(IP):
            return

        # Extract packet info
        packet_info = self.analyzer.extract_info(packet, self.local_ip)

        # Evaluate against rules
        action, matched_rule = self.evaluate_packet(packet_info)

        # Update statistics
        with self.stats_lock:
            self.stats["total_packets"] += 1
            if action == "allow":
                self.stats["allowed"] += 1
            else:
                self.stats["blocked"] += 1
                if packet_info["src_ip"]:
                    self.blocked_ips[packet_info["src_ip"]] += 1

            proto = packet_info["protocol"].lower()
            if proto in self.stats:
                self.stats[proto] += 1
            else:
                self.stats["other"] += 1

        # Build log entry
        log_entry = {
            **packet_info,
            "action": action,
            "rule_id": matched_rule.rule_id if matched_rule else "default",
        }

        # Store in recent packets
        with self.packets_lock:
            self.recent_packets.append(log_entry)
            if len(self.recent_packets) > self.max_recent:
                self.recent_packets.pop(0)

        # Log blocked packets
        if action == "block":
            self.logger.log_event(
                "PACKET_BLOCKED",
                f"{packet_info['protocol']} {packet_info['src_ip']}:{packet_info.get('src_port', 'N/A')} -> "
                f"{packet_info['dst_ip']}:{packet_info.get('dst_port', 'N/A')} "
                f"[Rule: {matched_rule.rule_id if matched_rule else 'rate-limit/default'}]"
            )

    # ── Engine Control ──────────────────────────────────────────────

    def start(self, packet_count=0):
        """Start capturing packets. packet_count=0 means infinite."""
        if not SCAPY_AVAILABLE:
            self.logger.log_event("ERROR", "Scapy not available. Install with: pip install scapy")
            return

        # Auto-load basic rules if none configured
        if not self.rules:
            self.logger.log_event("INFO", "No rules found, auto-loading basic preset")
            self.load_preset_basic()

        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.logger.log_event("FIREWALL_START", f"Monitoring on {self.interface or 'default'}")

        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                count=packet_count if packet_count > 0 else 0,
                store=False,
                stop_filter=lambda _: not self.is_running,
            )
        except PermissionError:
            self.logger.log_event("ERROR", "Root/admin privileges required for packet capture")
            raise
        except Exception as e:
            self.logger.log_event("ERROR", str(e))
            raise
        finally:
            self.is_running = False

    def start_async(self, packet_count=0):
        """Start firewall in a background thread."""
        thread = threading.Thread(target=self.start, args=(packet_count,), daemon=True)
        thread.start()
        return thread

    def stop(self):
        """Stop capturing packets."""
        self.is_running = False
        self.logger.log_event("FIREWALL_STOP", f"Total packets processed: {self.stats['total_packets']}")

    def get_stats(self):
        """Return current statistics."""
        with self.stats_lock:
            return dict(self.stats)

    def get_recent_packets(self, count=50):
        """Return recent packet log."""
        with self.packets_lock:
            return list(self.recent_packets[-count:])

    def get_top_blocked(self, count=10):
        """Return top blocked IPs."""
        sorted_ips = sorted(self.blocked_ips.items(), key=lambda x: x[1], reverse=True)
        return sorted_ips[:count]

    # ── Preset Rule Sets ────────────────────────────────────────────

    def load_preset_basic(self):
        """Load basic security rules."""
        self.add_rule("allow", protocol="tcp", dst_port=80, description="Allow HTTP")
        self.add_rule("allow", protocol="tcp", dst_port=443, description="Allow HTTPS")
        self.add_rule("allow", protocol="tcp", dst_port=53, description="Allow DNS (TCP)")
        self.add_rule("allow", protocol="udp", dst_port=53, description="Allow DNS (UDP)")
        self.add_rule("allow", protocol="tcp", dst_port=22, description="Allow SSH")
        self.add_rule("block", protocol="tcp", dst_port=23, description="Block Telnet (insecure)")
        self.add_rule("block", protocol="tcp", dst_port=3389, description="Block RDP")
        self.add_rule("allow", protocol="icmp", description="Allow ICMP (ping)")
        self.logger.log_event("PRESET_LOADED", "Basic security ruleset applied")

    def load_preset_strict(self):
        """Load strict security rules (whitelist approach)."""
        self.set_default_policy("block")
        self.add_rule("allow", protocol="tcp", dst_port=80, description="Allow HTTP")
        self.add_rule("allow", protocol="tcp", dst_port=443, description="Allow HTTPS")
        self.add_rule("allow", protocol="udp", dst_port=53, description="Allow DNS")
        self.add_rule("allow", protocol="tcp", dst_port=53, description="Allow DNS (TCP)")
        self.add_rule("block", protocol="icmp", description="Block ICMP (stealth)")
        self.add_rule("block", protocol="tcp", dst_port=23, description="Block Telnet")
        self.add_rule("block", protocol="tcp", dst_port=21, description="Block FTP")
        self.add_rule("block", protocol="tcp", dst_port=3389, description="Block RDP")
        self.add_rule("block", protocol="tcp", dst_port=445, description="Block SMB")
        self.add_rule("block", protocol="tcp", dst_port=135, description="Block RPC")
        self.logger.log_event("PRESET_LOADED", "Strict security ruleset applied (default: block)")

    # ── Save / Load Rules ───────────────────────────────────────────

    def save_rules(self, filepath="rules.json"):
        """Save current rules to JSON file."""
        data = {
            "default_policy": self.default_action,
            "rules": [r.to_dict() for r in self.rules],
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
        self.logger.log_event("RULES_SAVED", f"Saved {len(self.rules)} rules to {filepath}")

    def load_rules(self, filepath="rules.json"):
        """Load rules from JSON file."""
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            self.rules.clear()
            self.default_action = data.get("default_policy", "allow")
            for rd in data.get("rules", []):
                self.add_rule(
                    action=rd["action"],
                    direction=rd.get("direction", "both"),
                    protocol=rd.get("protocol") if rd.get("protocol") != "any" else None,
                    src_ip=rd.get("src_ip") if rd.get("src_ip") != "any" else None,
                    dst_ip=rd.get("dst_ip") if rd.get("dst_ip") != "any" else None,
                    src_port=rd.get("src_port") if rd.get("src_port") != "any" else None,
                    dst_port=rd.get("dst_port") if rd.get("dst_port") != "any" else None,
                    description=rd.get("description", ""),
                )
            self.logger.log_event("RULES_LOADED", f"Loaded {len(self.rules)} rules from {filepath}")
        except FileNotFoundError:
            self.logger.log_event("WARNING", f"Rules file not found: {filepath}")
        except json.JSONDecodeError:
            self.logger.log_event("ERROR", f"Invalid JSON in rules file: {filepath}")
