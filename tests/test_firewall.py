"""
PyreWall — Test Suite
Tests rule matching, rate limiting, preset loading, and packet evaluation.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
# Suppress scapy IPv6 warnings in this container
import logging
logging.getLogger("scapy").setLevel(logging.CRITICAL)

from app.firewall import FirewallEngine, FirewallRule, RateLimiter


@pytest.fixture
def fw():
    return FirewallEngine(local_ip="192.168.1.100")


# ── Rule Matching Tests ─────────────────────────────────────────────

class TestRuleMatching:
    def test_exact_ip_match(self, fw):
        fw.add_rule("block", src_ip="10.0.0.1", description="Block attacker")
        pkt = {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.100", "protocol": "TCP"}
        action, rule = fw.evaluate_packet(pkt)
        assert action == "block"
        assert rule is not None

    def test_port_match(self, fw):
        fw.add_rule("block", protocol="tcp", dst_port=23, description="Block Telnet")
        pkt = {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.100", "protocol": "TCP", "dst_port": 23}
        action, _ = fw.evaluate_packet(pkt)
        assert action == "block"

    def test_port_no_match(self, fw):
        fw.add_rule("block", protocol="tcp", dst_port=23, description="Block Telnet")
        pkt = {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.100", "protocol": "TCP", "dst_port": 80}
        action, _ = fw.evaluate_packet(pkt)
        assert action == "allow"  # default policy

    def test_protocol_match(self, fw):
        fw.add_rule("block", protocol="icmp", description="Block ping")
        pkt = {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.100", "protocol": "ICMP"}
        action, _ = fw.evaluate_packet(pkt)
        assert action == "block"

    def test_protocol_no_match(self, fw):
        fw.add_rule("block", protocol="icmp", description="Block ping")
        pkt = {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.100", "protocol": "TCP", "dst_port": 80}
        action, _ = fw.evaluate_packet(pkt)
        assert action == "allow"

    def test_direction_inbound(self, fw):
        fw.add_rule("block", direction="inbound", protocol="tcp", dst_port=22, description="Block inbound SSH")
        pkt_in = {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.100", "protocol": "TCP", "dst_port": 22, "direction": "inbound"}
        pkt_out = {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1", "protocol": "TCP", "dst_port": 22, "direction": "outbound"}
        assert fw.evaluate_packet(pkt_in)[0] == "block"
        assert fw.evaluate_packet(pkt_out)[0] == "allow"


# ── First Match Wins ────────────────────────────────────────────────

class TestFirstMatchWins:
    def test_allow_before_block(self, fw):
        fw.add_rule("allow", protocol="tcp", dst_port=80, description="Allow HTTP")
        fw.add_rule("block", protocol="tcp", description="Block all TCP")
        pkt = {"protocol": "TCP", "dst_port": 80, "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8"}
        action, rule = fw.evaluate_packet(pkt)
        assert action == "allow"
        assert rule.description == "Allow HTTP"

    def test_block_before_allow(self, fw):
        fw.add_rule("block", src_ip="10.0.0.1", description="Block bad IP")
        fw.add_rule("allow", protocol="tcp", dst_port=80, description="Allow HTTP")
        pkt = {"protocol": "TCP", "dst_port": 80, "src_ip": "10.0.0.1", "dst_ip": "5.6.7.8"}
        action, rule = fw.evaluate_packet(pkt)
        assert action == "block"


# ── Default Policy ──────────────────────────────────────────────────

class TestDefaultPolicy:
    def test_default_allow(self, fw):
        pkt = {"protocol": "TCP", "dst_port": 9999, "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8"}
        action, rule = fw.evaluate_packet(pkt)
        assert action == "allow"
        assert rule is None

    def test_default_block(self, fw):
        fw.set_default_policy("block")
        pkt = {"protocol": "TCP", "dst_port": 9999, "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8"}
        action, rule = fw.evaluate_packet(pkt)
        assert action == "block"
        assert rule is None


# ── Rate Limiter ────────────────────────────────────────────────────

class TestRateLimiter:
    def test_under_limit(self):
        rl = RateLimiter(max_connections=5, window_seconds=10)
        for _ in range(5):
            assert rl.check("10.0.0.1") is True

    def test_over_limit(self):
        rl = RateLimiter(max_connections=3, window_seconds=10)
        for _ in range(3):
            rl.check("10.0.0.1")
        assert rl.check("10.0.0.1") is False


# ── Rule Management ─────────────────────────────────────────────────

class TestRuleManagement:
    def test_add_rule(self, fw):
        rule = fw.add_rule("block", protocol="tcp", dst_port=23, description="Block Telnet")
        assert rule.rule_id == 1
        assert len(fw.rules) == 1

    def test_remove_rule(self, fw):
        fw.add_rule("block", protocol="tcp", dst_port=23, description="Block Telnet")
        fw.remove_rule(1)
        assert len(fw.rules) == 0

    def test_list_rules(self, fw):
        fw.add_rule("block", protocol="tcp", dst_port=23, description="Block Telnet")
        fw.add_rule("allow", protocol="tcp", dst_port=80, description="Allow HTTP")
        rules = fw.list_rules()
        assert len(rules) == 2
        assert rules[0]["action"] == "block"
        assert rules[1]["action"] == "allow"

    def test_hit_counter(self, fw):
        fw.add_rule("block", src_ip="10.0.0.1", description="Block attacker")
        pkt = {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.100", "protocol": "TCP"}
        fw.evaluate_packet(pkt)
        fw.evaluate_packet(pkt)
        fw.evaluate_packet(pkt)
        assert fw.rules[0].hit_count == 3


# ── Presets ──────────────────────────────────────────────────────────

class TestPresets:
    def test_basic_preset(self, fw):
        fw.load_preset_basic()
        assert len(fw.rules) >= 6
        assert fw.default_action == "allow"

    def test_strict_preset(self, fw):
        fw.load_preset_strict()
        assert fw.default_action == "block"
        # HTTP should be allowed
        pkt = {"protocol": "TCP", "dst_port": 80, "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8"}
        action, _ = fw.evaluate_packet(pkt)
        assert action == "allow"
        # Random port should be blocked
        pkt2 = {"protocol": "TCP", "dst_port": 9999, "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8"}
        action2, _ = fw.evaluate_packet(pkt2)
        assert action2 == "block"
