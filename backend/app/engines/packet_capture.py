"""NetGuard AI — Packet Capture Engine.

Responsible for sniffing live network traffic (via Scapy), parsing raw
packets into structured dicts, batching them, and dispatching the
results to the database and WebSocket consumers.
"""

from __future__ import annotations

import time
import random
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

from flask import Flask

from app.extensions import db


def generate_mac() -> str:
    """Generate a random MAC address."""
    return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])


class PacketCaptureEngine:
    """Captures and processes network packets in a background thread.

    Parameters
    ----------
    app:
        Optional Flask application.  If given, ``init_app`` is called
        immediately.
    """

    def __init__(self, app: Optional[Flask] = None) -> None:
        self._running: bool = False
        self._buffer: List[Dict[str, Any]] = []
        self._thread: Optional[threading.Thread] = None
        self._app: Optional[Flask] = None
        self._last_flush_time: float = time.time()

        if app is not None:
            self.init_app(app)

    # ── Flask integration ─────────────────────────────────────────────

    def init_app(self, app: Flask) -> None:
        """Bind the engine to a Flask application.

        Parameters
        ----------
        app:
            The Flask application instance.
        """
        self._app = app
        # Store engine reference on the app for convenient access.
        app.extensions["packet_capture"] = self

    # ── Public API ────────────────────────────────────────────────────

    def start(self) -> None:
        """Begin capturing packets in a background thread."""
        if self._running:
            return

        self._running = True
        self._buffer.clear()
        self._last_flush_time = time.time()

        self._thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self._thread.start()

        if self._app:
            self._app.logger.info("Packet Capture Engine started.")

    def stop(self) -> None:
        """Gracefully stop the packet-capture thread."""
        if not self._running:
            return

        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)

        # Flush any remaining packets
        self._process_batch()

        if self._app:
            self._app.logger.info("Packet Capture Engine stopped.")

    # ── Internal methods ──────────────────────────────────────────────

    def _sniff_packets(self) -> None:
        """Entry-point for the background sniffing thread (Scapy/Demo)."""
        if not self._app:
            return

        demo_mode = self._app.config.get("DEMO_MODE", True)

        if demo_mode:
            self._run_demo_generator()
        else:
            self._run_scapy_sniffer()

    def _run_demo_generator(self) -> None:
        """Generate synthetic traffic patterns for demonstration."""
        protocols = ["TCP", "UDP", "DNS", "ICMP", "HTTP", "HTTPS", "SSH", "ARP"]
        internal_ips = [
            "192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.100",
            "10.0.0.5", "10.0.0.10"
        ]
        external_ips = [
            "8.8.8.8", "1.1.1.1", "172.217.14.206", "104.244.42.193", "45.33.32.156"
        ]

        batch_interval = self._app.config.get("PACKET_BATCH_INTERVAL", 2) if self._app else 2

        while self._running:
            proto = random.choice(protocols)
            is_outbound = random.random() < 0.6

            if is_outbound:
                src_ip = random.choice(internal_ips)
                dst_ip = random.choice(external_ips)
            else:
                src_ip = random.choice(external_ips)
                dst_ip = random.choice(internal_ips)

            src_port = random.randint(1024, 65535) if proto != "ICMP" and proto != "ARP" else None
            dst_port = None
            payload = ""

            if proto == "HTTP":
                dst_port = random.choice([80, 8080])
                payload = f"GET /api/v1/status HTTP/1.1\r\nHost: {dst_ip}\r\n\r\n"
            elif proto == "HTTPS":
                dst_port = random.choice([443, 8443])
                payload = "TLS Client Hello (v1.3)"
            elif proto == "DNS":
                dst_port = 53
                payload = f"DNS Query: {random.choice(['google.com', 'cisco.com', 'stealthwatch.com'])}"
            elif proto == "SSH":
                dst_port = 22
                payload = "SSH-2.0-OpenSSH_8.9p1"
            elif proto == "TCP":
                dst_port = random.choice([3306, 6379, 21, 23])
                payload = "TCP Connection Handshake"
            elif proto == "UDP":
                dst_port = random.choice([123, 161, 500])
                payload = "UDP Datagram payload"
            elif proto == "ARP":
                payload = f"ARP Who has {dst_ip}? Tell {src_ip}"
            else:
                payload = "ICMP Ping request"

            packet_data = {
                "timestamp": datetime.utcnow(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
                "packet_size": random.randint(40, 1500),
                "ttl": random.choice([64, 128]),
                "src_mac": generate_mac(),
                "dst_mac": generate_mac(),
                "payload_preview": payload
            }

            self._dispatch_packet(packet_data)

            # Check periodic flush condition
            if time.time() - self._last_flush_time >= batch_interval:
                self._process_batch()

            # Sleep briefly to rate limit packet generation (approx 2-5 packets/sec)
            time.sleep(random.uniform(0.2, 0.5))

    def _run_scapy_sniffer(self) -> None:
        """Capture packet structures from a physical interface."""
        try:
            from scapy.all import sniff
        except ImportError:
            if self._app:
                self._app.logger.warning("Scapy import failed. Falling back to Demo generator.")
            self._run_demo_generator()
            return

        interface = self._app.config.get("PACKET_CAPTURE_INTERFACE", "eth0") if self._app else "eth0"
        batch_interval = self._app.config.get("PACKET_BATCH_INTERVAL", 2) if self._app else 2

        def packet_handler(packet: Any) -> None:
            try:
                parsed = self._parse_packet(packet)
                if parsed:
                    self._dispatch_packet(parsed)
            except Exception as e:
                if self._app:
                    self._app.logger.error(f"Error parsing raw packet: {e}")

        if self._app:
            self._app.logger.info(f"Starting Scapy sniff loop on interface: {interface}")

        while self._running:
            # Sniff with a short timeout to check self._running flag condition
            sniff(iface=interface, prn=packet_handler, store=0, timeout=1.0)

            # Check periodic flush
            if time.time() - self._last_flush_time >= batch_interval:
                self._process_batch()

    def _parse_packet(self, packet: Any) -> Dict[str, Any]:
        """Convert a raw Scapy packet into a structured dictionary."""
        packet_data: Dict[str, Any] = {
            "timestamp": datetime.utcnow(),
            "src_ip": "0.0.0.0",
            "dst_ip": "0.0.0.0",
            "src_port": None,
            "dst_port": None,
            "protocol": "UNKNOWN",
            "packet_size": len(packet),
            "ttl": None,
            "src_mac": None,
            "dst_mac": None,
            "payload_preview": None
        }

        # Parse Ethernet layer
        if packet.haslayer("Ether"):
            packet_data["src_mac"] = packet["Ether"].src
            packet_data["dst_mac"] = packet["Ether"].dst

        # Parse Network layer
        if packet.haslayer("IP"):
            packet_data["src_ip"] = packet["IP"].src
            packet_data["dst_ip"] = packet["IP"].dst
            packet_data["ttl"] = packet["IP"].ttl
            packet_data["protocol"] = "IPv4"
        elif packet.haslayer("IPv6"):
            packet_data["src_ip"] = packet["IPv6"].src
            packet_data["dst_ip"] = packet["IPv6"].dst
            packet_data["ttl"] = packet["IPv6"].hlim
            packet_data["protocol"] = "IPv6"

        # Parse Transport layer
        if packet.haslayer("TCP"):
            packet_data["protocol"] = "TCP"
            packet_data["src_port"] = packet["TCP"].sport
            packet_data["dst_port"] = packet["TCP"].dport

            # Identify common sub-protocols
            if packet_data["dst_port"] in [80, 8080] or packet_data["src_port"] in [80, 8080]:
                packet_data["protocol"] = "HTTP"
            elif packet_data["dst_port"] in [443, 8443] or packet_data["src_port"] in [443, 8443]:
                packet_data["protocol"] = "HTTPS"
            elif packet_data["dst_port"] == 22 or packet_data["src_port"] == 22:
                packet_data["protocol"] = "SSH"

            # Parse text payload preview
            if packet.haslayer("Raw"):
                try:
                    payload = packet["Raw"].load
                    packet_data["payload_preview"] = payload[:100].decode("utf-8", errors="ignore")
                except Exception:
                    pass

        elif packet.haslayer("UDP"):
            packet_data["protocol"] = "UDP"
            packet_data["src_port"] = packet["UDP"].sport
            packet_data["dst_port"] = packet["UDP"].dport

            if packet.haslayer("DNS"):
                packet_data["protocol"] = "DNS"
                # Basic DNS query preview extraction if possible
                if packet.haslayer("DNSQR"):
                    packet_data["payload_preview"] = f"DNS Query: {packet['DNSQR'].qname.decode('utf-8', errors='ignore')}"
            
            if not packet_data["payload_preview"] and packet.haslayer("Raw"):
                try:
                    payload = packet["Raw"].load
                    packet_data["payload_preview"] = payload[:100].decode("utf-8", errors="ignore")
                except Exception:
                    pass

        elif packet.haslayer("ICMP"):
            packet_data["protocol"] = "ICMP"
            packet_data["payload_preview"] = "ICMP echo-request/reply"

        elif packet.haslayer("ARP"):
            packet_data["protocol"] = "ARP"
            packet_data["src_ip"] = packet["ARP"].psrc
            packet_data["dst_ip"] = packet["ARP"].pdst
            op = "who-has" if packet["ARP"].op == 1 else "is-at"
            packet_data["payload_preview"] = f"ARP {op} {packet['ARP'].pdst} Tell {packet['ARP'].psrc}"

        return packet_data

    def _dispatch_packet(self, packet_data: Dict[str, Any]) -> None:
        """Send a single parsed packet to downstream consumers and websocket."""
        self._buffer.append(packet_data)

        # Notify threat detection and discovery engines if registered
        if self._app:
            tde = self._app.extensions.get("threat_detection")
            if tde:
                try:
                    tde.analyze_packet(packet_data)
                except Exception as e:
                    self._app.logger.error(f"ThreatDetectionEngine failed packet analysis: {e}")

            nde = self._app.extensions.get("network_discovery")
            if nde:
                try:
                    nde.process_packet(packet_data)
                except Exception as e:
                    self._app.logger.error(f"NetworkDiscoveryEngine failed packet process: {e}")

        # Push real-time packet summary over WebSocket
        from app.websocket.events import broadcast_packet
        from app.utils.formatters import format_packet_summary
        
        ws_data = format_packet_summary(packet_data)
        # Convert timestamp to iso string for JSON serialization
        if isinstance(ws_data.get("timestamp"), datetime):
            ws_data["timestamp"] = ws_data["timestamp"].isoformat()
            
        broadcast_packet(ws_data)

        # Batch database write triggers
        batch_size = self._app.config.get("PACKET_BATCH_SIZE", 100) if self._app else 100
        if len(self._buffer) >= batch_size:
            self._process_batch()

    def _process_batch(self) -> None:
        """Flush the current buffer, persist packets, and broadcast."""
        if not self._buffer:
            return

        batch = list(self._buffer)
        self._buffer.clear()
        self._last_flush_time = time.time()

        if self._app:
            with self._app.app_context():
                try:
                    from app.services.packet_service import save_packets_batch
                    save_packets_batch(batch)
                except Exception as e:
                    self._app.logger.error(f"Failed to save packet batch to database: {e}")
