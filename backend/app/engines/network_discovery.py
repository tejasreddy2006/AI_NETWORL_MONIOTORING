"""NetGuard AI — Network Discovery Engine.

Maintains an up-to-date inventory of devices and the communication
links between them by inspecting every parsed packet.  Produces the
data that powers the topology map on the front-end.
"""

from __future__ import annotations

import time
import ipaddress
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from flask import Flask

from app.extensions import db
from app.models.device import Device, DeviceLink, HealthStatus


class NetworkDiscoveryEngine:
    """Discovers and classifies devices from observed traffic.

    Parameters
    ----------
    app:
        Optional Flask application.
    """

    def __init__(self, app: Optional[Flask] = None) -> None:
        self._known_devices: Dict[str, Dict[str, Any]] = {}
        self._app: Optional[Flask] = None

        # Link accumulator to rate-limit database queries: (src_ip, dst_ip) -> counts/timestamps
        self._link_accumulator: Dict[tuple[str, str], Dict[str, Any]] = defaultdict(
            lambda: {"packets": 0, "bytes": 0, "first_seen": None, "last_seen": None}
        )
        self._last_link_flush: float = time.time()
        self._last_health_check: float = time.time()

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
        app.extensions["network_discovery"] = self

    # ── Public API ────────────────────────────────────────────────────

    def process_packet(self, packet_data: Dict[str, Any]) -> None:
        """Inspect a parsed packet to discover / update devices and links.

        Parameters
        ----------
        packet_data:
            Parsed packet dictionary.
        """
        src_ip = packet_data.get("src_ip")
        dst_ip = packet_data.get("dst_ip")
        
        if not src_ip or not dst_ip or src_ip == "0.0.0.0" or dst_ip == "0.0.0.0":
            return

        # Lazy load devices from database into memory cache
        self._ensure_cache_loaded()

        now = time.time()
        timestamp = packet_data.get("timestamp") or datetime.utcnow()

        # Update or register source device
        self._register_or_update_ip(
            ip=src_ip,
            mac=packet_data.get("src_mac"),
            port=packet_data.get("src_port"),
            ttl=packet_data.get("ttl"),
            timestamp=timestamp
        )

        # Update or register destination device
        self._register_or_update_ip(
            ip=dst_ip,
            mac=packet_data.get("dst_mac"),
            port=packet_data.get("dst_port"),
            ttl=packet_data.get("ttl"),
            timestamp=timestamp
        )

        # Accumulate traffic links in memory
        self._update_links(src_ip, dst_ip, packet_data.get("packet_size", 0), timestamp)

        # Periodically flush links to the database (every 10 seconds)
        if now - self._last_link_flush >= 10.0:
            self._flush_accumulated_links()

        # Periodically update device health scores based on active alerts (every 30 seconds)
        if now - self._last_health_check >= 30.0:
            self._update_health_status()
            self._last_health_check = now

    def get_topology(self) -> Dict[str, Any]:
        """Return the current topology graph (nodes + edges).

        Returns
        -------
        dict
            ``{"nodes": [...], "edges": [...]}`` suitable for the front-end.
        """
        from app.services.topology_service import get_topology_graph

        if self._app:
            with self._app.app_context():
                return get_topology_graph()
        return {"nodes": [], "edges": []}

    # ── Internal helpers ──────────────────────────────────────────────

    def _ensure_cache_loaded(self) -> None:
        """Prefill known devices cache from database."""
        if not self._known_devices and self._app:
            with self._app.app_context():
                try:
                    devices = Device.query.all()
                    for dev in devices:
                        self._known_devices[dev.ip_address] = {
                            "id": dev.id,
                            "mac": dev.mac_address,
                            "ports": [],
                            "ttl": None,
                            "device_type": dev.device_type,
                            "health": dev.health_status,
                            "last_db_update": time.time()
                        }
                except Exception as e:
                    self._app.logger.error(f"Failed to load devices cache: {e}")

    def _register_or_update_ip(
        self,
        ip: str,
        mac: Optional[str],
        port: Optional[int],
        ttl: Optional[int],
        timestamp: datetime
    ) -> None:
        """Insert a new device or update last_seen timestamp in database."""
        if not self._app:
            return

        now = time.time()

        if ip not in self._known_devices:
            # Create a brand new device
            with self._app.app_context():
                try:
                    # Double-check database in case of race condition in concurrent packets
                    exists = Device.query.filter(Device.ip_address == ip).first()
                    if exists:
                        self._known_devices[ip] = {
                            "id": exists.id,
                            "mac": exists.mac_address,
                            "ports": [port] if port else [],
                            "ttl": ttl,
                            "device_type": exists.device_type,
                            "health": exists.health_status,
                            "last_db_update": now
                        }
                        return

                    # Heuristic classification
                    ports = [port] if port else []
                    dev_type = self._classify_device(ip, mac, ports, ttl)
                    
                    is_private = False
                    try:
                        is_private = ipaddress.ip_address(ip).is_private
                    except ValueError:
                        pass
                        
                    vendor = "Cisco" if ip.endswith(".1") else ("Private Host" if is_private else "External Provider")

                    dev = Device(
                        ip_address=ip,
                        mac_address=mac,
                        device_type=dev_type,
                        hostname=f"host-{ip.replace('.', '-')}",
                        vendor=vendor,
                        os_guess="Cisco IOS" if dev_type == "router" else ("Linux" if ttl == 64 else ("Windows" if ttl == 128 else "Unknown")),
                        health_status=HealthStatus.HEALTHY,
                        first_seen=timestamp,
                        last_seen=timestamp
                    )
                    db.session.add(dev)
                    db.session.commit()

                    self._known_devices[ip] = {
                        "id": dev.id,
                        "mac": mac,
                        "ports": ports,
                        "ttl": ttl,
                        "device_type": dev_type,
                        "health": HealthStatus.HEALTHY,
                        "last_db_update": now
                    }

                except Exception as e:
                    self._app.logger.error(f"Failed to create discovered device for {ip}: {e}")
        else:
            # Update cache ports and database last_seen (rate-limited to every 30 seconds)
            cache = self._known_devices[ip]
            if port and port not in cache["ports"] and len(cache["ports"]) < 20:
                cache["ports"].append(port)
                # Re-evaluate device classification if new ports are observed
                new_type = self._classify_device(ip, mac, cache["ports"], ttl or cache["ttl"])
                if new_type != cache["device_type"]:
                    cache["device_type"] = new_type
                    with self._app.app_context():
                        try:
                            dev = Device.query.get(cache["id"])
                            if dev:
                                dev.device_type = new_type
                                db.session.commit()
                        except Exception:
                            pass

            if now - cache.get("last_db_update", 0) >= 30.0:
                cache["last_db_update"] = now
                with self._app.app_context():
                    try:
                        dev = Device.query.get(cache["id"])
                        if dev:
                            dev.last_seen = timestamp
                            db.session.commit()
                    except Exception:
                        pass

    def _classify_device(
        self,
        ip: str,
        mac: Optional[str],
        ports: List[int],
        ttl: Optional[int],
    ) -> str:
        """Heuristically determine the device type."""
        ip_str = str(ip)

        # Heuristic 1: default routers
        if ip_str.endswith(".1") or ip_str.endswith(".254"):
            return "router"

        # Heuristic 2: check common server ports
        server_ports = {80, 443, 8080, 8443, 3306, 6379, 22, 21, 25, 587, 8000}
        if any(p in server_ports for p in ports):
            return "server"

        # Heuristic 3: check common switch management / network utilities ports
        switch_ports = {161, 162}
        if any(p in switch_ports for p in ports):
            return "switch"

        # Heuristic 4: TTL signatures
        if ttl == 255:
            return "router"
        elif ttl == 64:
            # Linux host (could be client PC, Server, or IoT depending on ports)
            return "pc"
        elif ttl == 128:
            # Windows host
            return "pc"

        return "unknown"

    def _update_links(self, src_ip: str, dst_ip: str, packet_size: int, timestamp: datetime) -> None:
        """Accumulate traffic in memory before batch flushing to DeviceLink."""
        key = (src_ip, dst_ip)
        acc = self._link_accumulator[key]
        acc["packets"] += 1
        acc["bytes"] += packet_size
        if not acc["first_seen"]:
            acc["first_seen"] = timestamp
        acc["last_seen"] = timestamp

    def _flush_accumulated_links(self) -> None:
        """Flush memory-accumulated link stats into database records."""
        if not self._link_accumulator or not self._app:
            return

        self._last_link_flush = time.time()
        flush_data = dict(self._link_accumulator)
        self._link_accumulator.clear()

        with self._app.app_context():
            try:
                for (src_ip, dst_ip), stats in flush_data.items():
                    src_cache = self._known_devices.get(src_ip)
                    dst_cache = self._known_devices.get(dst_ip)

                    if not src_cache or not dst_cache:
                        continue

                    # Query existing link or create new
                    link = DeviceLink.query.filter(
                        DeviceLink.source_device_id == src_cache["id"],
                        DeviceLink.target_device_id == dst_cache["id"]
                    ).first()

                    if link:
                        link.packet_count += stats["packets"]
                        link.total_bytes += stats["bytes"]
                        link.last_seen = stats["last_seen"]
                    else:
                        link = DeviceLink(
                            source_device_id=src_cache["id"],
                            target_device_id=dst_cache["id"],
                            packet_count=stats["packets"],
                            total_bytes=stats["bytes"],
                            first_seen=stats["first_seen"],
                            last_seen=stats["last_seen"]
                        )
                        db.session.add(link)

                db.session.commit()
            except Exception as e:
                self._app.logger.error(f"Failed to flush device links to database: {e}")

    def _update_health_status(self) -> None:
        """Re-evaluate the health status of all known devices based on active alerts."""
        if not self._app:
            return

        with self._app.app_context():
            try:
                from app.models.alert import Alert
                
                # Fetch unresolved alerts
                active_alerts = Alert.query.filter(Alert.is_resolved == False).all()
                ip_severity_map = defaultdict(list)
                
                for alert in active_alerts:
                    ip_severity_map[alert.source_ip].append(alert.severity.name if hasattr(alert.severity, "name") else str(alert.severity))
                    ip_severity_map[alert.destination_ip].append(alert.severity.name if hasattr(alert.severity, "name") else str(alert.severity))

                devices = Device.query.all()
                for dev in devices:
                    ip = dev.ip_address
                    severities = ip_severity_map.get(ip, [])

                    new_status = HealthStatus.HEALTHY
                    if "CRITICAL" in severities:
                        new_status = HealthStatus.CRITICAL
                    elif "HIGH" in severities or "MEDIUM" in severities:
                        new_status = HealthStatus.WARNING

                    if dev.health_status != new_status:
                        dev.health_status = new_status
                        # Sync memory cache
                        if ip in self._known_devices:
                            self._known_devices[ip]["health"] = new_status

                db.session.commit()
            except Exception as e:
                self._app.logger.error(f"Failed to update device health statuses: {e}")
