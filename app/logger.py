"""
PyreWall — Security Event Logger
Logs firewall events to both console and rotating log files.
"""
import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime


class SecurityLogger:
    """Structured logging for firewall events."""

    def __init__(self, log_dir="logs", log_file="firewall.log"):
        os.makedirs(log_dir, exist_ok=True)
        self.logger = logging.getLogger("pyrewall")
        self.logger.setLevel(logging.INFO)

        # Avoid duplicate handlers
        if not self.logger.handlers:
            # File handler (rotating, 5 MB max, 3 backups)
            fh = RotatingFileHandler(
                os.path.join(log_dir, log_file),
                maxBytes=5_000_000,
                backupCount=3,
            )
            fh.setLevel(logging.INFO)
            fh.setFormatter(logging.Formatter(
                "%(asctime)s | %(levelname)-7s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            ))
            self.logger.addHandler(fh)

            # Console handler
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            ch.setFormatter(logging.Formatter(
                "\033[90m%(asctime)s\033[0m | %(levelname)-7s | %(message)s",
                datefmt="%H:%M:%S",
            ))
            self.logger.addHandler(ch)

    def log_event(self, event_type, details=""):
        """Log a firewall event."""
        msg = f"[{event_type}] {details}"
        if event_type in ("PACKET_BLOCKED", "RATE_LIMITED", "ERROR"):
            self.logger.warning(msg)
        elif event_type in ("FIREWALL_START", "FIREWALL_STOP", "RULE_ADDED", "PRESET_LOADED"):
            self.logger.info(msg)
        else:
            self.logger.info(msg)

    def log_packet(self, packet_info, action):
        """Log a single packet decision."""
        src = f"{packet_info.get('src_ip', '?')}:{packet_info.get('src_port', '?')}"
        dst = f"{packet_info.get('dst_ip', '?')}:{packet_info.get('dst_port', '?')}"
        proto = packet_info.get("protocol", "?")
        self.logger.info(f"[{action.upper()}] {proto} {src} -> {dst}")
