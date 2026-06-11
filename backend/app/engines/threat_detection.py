"""NetGuard AI — Threat Detection Engine.

Analyses parsed packet data in real time and raises ``Alert`` records
when suspicious patterns are detected (port scans, DDoS, ICMP floods,
DNS abuse, brute-force attempts, statistical anomalies).
"""

from __future__ import annotations

import time
import math
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from flask import Flask

from app.extensions import db
from app.models.alert import Alert, SeverityLevel
from app.websocket.events import broadcast_alert


class ThreatDetectionEngine:
    """Stateful engine that analyses packets for threat indicators.

    Parameters
    ----------
    app:
        Optional Flask application.
    """

    def __init__(self, app: Optional[Flask] = None) -> None:
        self._app: Optional[Flask] = None

        # Stateful trackers: IP -> list of timestamps
        self._port_scan_tracker: Dict[str, List[tuple[float, int]]] = defaultdict(list)
        self._ddos_tracker: Dict[str, List[float]] = defaultdict(list)
        self._icmp_tracker: Dict[str, List[float]] = defaultdict(list)
        self._dns_tracker: Dict[str, List[float]] = defaultdict(list)
        self._brute_force_tracker: Dict[str, List[tuple[float, int]]] = defaultdict(list)

        # Traffic volume stats (for anomaly detection)
        self._volume_buckets: Dict[int, int] = defaultdict(int)  # epoch_10s -> packet_count
        self._volume_history: List[int] = []  # list of recent packet counts per 10s

        # Cooldown tracker to prevent alert spamming: (threat_type, src_ip, dst_ip) -> timestamp
        self._alert_cooldowns: Dict[tuple[str, str, str], float] = {}

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
        app.extensions["threat_detection"] = self

    # ── Public API ────────────────────────────────────────────────────

    def analyze_packet(self, packet_data: Dict[str, Any]) -> None:
        """Run all detection heuristics against a single parsed packet.

        Parameters
        ----------
        packet_data:
            Parsed packet dictionary emitted by the capture engine.
        """
        # Stateful tracking based on timestamps
        self._detect_port_scan(packet_data)
        self._detect_ddos(packet_data)
        self._detect_icmp_flood(packet_data)
        self._detect_dns_abuse(packet_data)
        self._detect_brute_force(packet_data)
        self._detect_anomaly(packet_data)

    # ── Detection heuristics ──────────────────────────────────────────

    def _detect_port_scan(self, packet_data: Dict[str, Any]) -> None:
        """Detect port-scanning behaviour from a single source.

        Rule: > 15 unique destination ports queried in 60 seconds from same IP.
        """
        src_ip = packet_data.get("src_ip")
        dst_port = packet_data.get("dst_port")
        protocol = packet_data.get("protocol")

        if not src_ip or dst_port is None or protocol not in ["TCP", "UDP"]:
            return

        now = time.time()
        # Keep only ports scanned in last 60 seconds
        self._port_scan_tracker[src_ip] = [
            (t, port) for t, port in self._port_scan_tracker[src_ip] if now - t <= 60
        ]
        
        # Add current port probe
        self._port_scan_tracker[src_ip].append((now, dst_port))

        unique_ports = {port for _, port in self._port_scan_tracker[src_ip]}

        if len(unique_ports) > 15:
            # Trigger port scan alert
            self._create_alert(
                threat_type="Port Scan Detected",
                severity="HIGH",
                source_ip=src_ip,
                dest_ip=packet_data.get("dst_ip", "0.0.0.0"),
                description=f"Host probed {len(unique_ports)} unique ports in the last 60 seconds.",
                evidence=f"Queried ports: {sorted(list(unique_ports))}",
                recommendation=f"Isolate source IP {src_ip} at network border. Implement firewall block rules."
            )

    def _detect_ddos(self, packet_data: Dict[str, Any]) -> None:
        """Detect volumetric DDoS patterns.

        Rule: > 300 packets targeting a single IP in 10 seconds.
        """
        dst_ip = packet_data.get("dst_ip")
        if not dst_ip or dst_ip == "0.0.0.0":
            return

        now = time.time()
        # Keep packet timestamps in last 10 seconds
        self._ddos_tracker[dst_ip] = [t for t in self._ddos_tracker[dst_ip] if now - t <= 10]
        self._ddos_tracker[dst_ip].append(now)

        pkt_count = len(self._ddos_tracker[dst_ip])
        if pkt_count > 300:
            self._create_alert(
                threat_type="DDoS Attack Detected",
                severity="CRITICAL",
                source_ip=packet_data.get("src_ip", "0.0.0.0"),
                dest_ip=dst_ip,
                description=f"Destination IP received {pkt_count} packets in under 10 seconds. High volume traffic flood.",
                evidence=f"Traffic rate: {pkt_count / 10:.1f} packets/second. Target: {dst_ip}",
                recommendation=f"Enable DDoS mitigation profiles. Configure traffic rate limiting to target IP {dst_ip}."
            )

    def _detect_icmp_flood(self, packet_data: Dict[str, Any]) -> None:
        """Detect ICMP flood attacks.

        Rule: > 50 ICMP packets from single source in 10 seconds.
        """
        src_ip = packet_data.get("src_ip")
        protocol = packet_data.get("protocol")

        if not src_ip or protocol != "ICMP":
            return

        now = time.time()
        self._icmp_tracker[src_ip] = [t for t in self._icmp_tracker[src_ip] if now - t <= 10]
        self._icmp_tracker[src_ip].append(now)

        icmp_count = len(self._icmp_tracker[src_ip])
        if icmp_count > 50:
            self._create_alert(
                threat_type="ICMP Flood Detected",
                severity="HIGH",
                source_ip=src_ip,
                dest_ip=packet_data.get("dst_ip", "0.0.0.0"),
                description=f"Host sent {icmp_count} ICMP echo requests in 10 seconds. Potential ping flood.",
                evidence=f"ICMP rate: {icmp_count / 10:.1f} pps from source {src_ip}",
                recommendation=f"Block ICMP echo requests from {src_ip}. Enable ICMP flood guard on firewall."
            )

    def _detect_dns_abuse(self, packet_data: Dict[str, Any]) -> None:
        """Detect DNS amplification or tunnelling abuse.

        Rule: > 40 DNS queries from single source in 10 seconds.
        """
        src_ip = packet_data.get("src_ip")
        protocol = packet_data.get("protocol")

        if not src_ip or protocol != "DNS":
            return

        now = time.time()
        self._dns_tracker[src_ip] = [t for t in self._dns_tracker[src_ip] if now - t <= 10]
        self._dns_tracker[src_ip].append(now)

        dns_count = len(self._dns_tracker[src_ip])
        if dns_count > 40:
            self._create_alert(
                threat_type="DNS Abuse Pattern",
                severity="MEDIUM",
                source_ip=src_ip,
                dest_ip=packet_data.get("dst_ip", "0.0.0.0"),
                description=f"Host generated {dns_count} DNS queries in 10 seconds. High frequency DNS behavior.",
                evidence=f"DNS Queries rate: {dns_count / 10:.1f} qps. Payload: {packet_data.get('payload_preview')}",
                recommendation=f"Audit DNS query patterns for {src_ip} to detect DNS tunnel exfiltration or botnet communication."
            )

    def _detect_brute_force(self, packet_data: Dict[str, Any]) -> None:
        """Detect brute-force login attempts (SSH/RDP/etc.).

        Rule: > 8 connections to same login port (22, 23, 3389) from same source in 30 seconds.
        """
        src_ip = packet_data.get("src_ip")
        dst_port = packet_data.get("dst_port")
        protocol = packet_data.get("protocol")

        if not src_ip or dst_port not in [22, 23, 3389] or protocol != "TCP":
            return

        now = time.time()
        self._brute_force_tracker[src_ip] = [
            (t, port) for t, port in self._brute_force_tracker[src_ip] if now - t <= 30
        ]
        self._brute_force_tracker[src_ip].append((now, dst_port))

        port_connections = [port for _, port in self._brute_force_tracker[src_ip] if port == dst_port]
        con_count = len(port_connections)

        if con_count > 8:
            port_name = "SSH" if dst_port == 22 else ("RDP" if dst_port == 3389 else "Telnet")
            self._create_alert(
                threat_type="Brute Force Attempt",
                severity="HIGH",
                source_ip=src_ip,
                dest_ip=packet_data.get("dst_ip", "0.0.0.0"),
                description=f"Host initiated {con_count} connection attempts to restricted service {port_name} (port {dst_port}) in 30 seconds.",
                evidence=f"Brute force attempt count: {con_count} connections to port {dst_port} from {src_ip}",
                recommendation=f"Temporary block IP {src_ip} at network edge. Enable fail2ban or multi-factor authentication locks."
            )

    def _detect_anomaly(self, packet_data: Dict[str, Any]) -> None:
        """Detect statistical anomalies in traffic patterns.

        Rule: Sudden traffic volume spike (3x standard deviation above recent average).
        """
        now = time.time()
        bucket_10s = int(now // 10) * 10
        self._volume_buckets[bucket_10s] += 1

        # Keep volume history clean (last 5 minutes = 30 buckets of 10s)
        outdated_keys = [k for k in self._volume_buckets if now - k > 300]
        for k in outdated_keys:
            # Shift value into historical list before deleting from active buckets
            self._volume_history.append(self._volume_buckets[k])
            del self._volume_buckets[k]

        # Keep history list capped at 50 elements
        if len(self._volume_history) > 50:
            self._volume_history = self._volume_history[-50:]

        current_count = self._volume_buckets[bucket_10s]

        # Require a minimum history to establish standard deviation baseline
        if len(self._volume_history) >= 10:
            mean = sum(self._volume_history) / len(self._volume_history)
            variance = sum((x - mean) ** 2 for x in self._volume_history) / len(self._volume_history)
            std_dev = math.sqrt(variance)

            # Check if current count is highly abnormal (greater than mean + 3 standard deviations)
            if std_dev > 2.0 and current_count > (mean + 3 * std_dev):
                self._create_alert(
                    threat_type="Traffic Anomaly",
                    severity="MEDIUM",
                    source_ip=packet_data.get("src_ip", "0.0.0.0"),
                    dest_ip=packet_data.get("dst_ip", "0.0.0.0"),
                    description=f"Network traffic volume surged statistically. Volume bucket has {current_count} packets in 10s.",
                    evidence=f"Volume: {current_count} packets. Baseline mean: {mean:.1f}, std_dev: {std_dev:.1f}",
                    recommendation="Review flow records and traffic distribution charts. Inspect active services for performance spikes."
                )

    # ── Alert creation ────────────────────────────────────────────────

    def _create_alert(
        self,
        threat_type: str,
        severity: str,
        source_ip: str,
        dest_ip: str,
        description: str,
        evidence: str,
        recommendation: str,
    ) -> None:
        """Persist an ``Alert`` record and broadcast it via WebSocket."""
        # Cooldown guard: prevent generating duplicate alerts for the same threat-link within 30 seconds
        cooldown_key = (threat_type, source_ip, dest_ip)
        now = time.time()
        if cooldown_key in self._alert_cooldowns:
            if now - self._alert_cooldowns[cooldown_key] < 30.0:
                return

        self._alert_cooldowns[cooldown_key] = now

        if self._app:
            with self._app.app_context():
                try:
                    severity_enum = SeverityLevel[severity.upper()]
                except KeyError:
                    severity_enum = SeverityLevel.LOW

                alert = Alert(
                    timestamp=datetime.utcnow(),
                    threat_type=threat_type,
                    severity=severity_enum,
                    source_ip=source_ip,
                    destination_ip=dest_ip,
                    description=description,
                    raw_evidence=evidence,
                    recommended_action=recommendation,
                    is_resolved=False
                )
                db.session.add(alert)
                db.session.commit()

                # Broadcast over WebSocket to all clients
                try:
                    broadcast_alert(alert.to_dict())
                except Exception as e:
                    self._app.logger.error(f"WebSocket broadcast_alert failed: {e}")
