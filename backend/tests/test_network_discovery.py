"""NetGuard AI — Network Discovery Engine Tests.

Tests the passive discovery, classification, link creation, and health updates.
"""

import pytest
from datetime import datetime
from app import create_app
from app.extensions import db
from app.models.device import Device, DeviceLink, HealthStatus
from app.models.alert import Alert, SeverityLevel
from app.engines.network_discovery import NetworkDiscoveryEngine


@pytest.fixture
def app():
    """Create Flask application configured for testing."""
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def engine(app):
    """Create a NetworkDiscoveryEngine instance linked to the app."""
    return NetworkDiscoveryEngine(app)


def test_passive_device_discovery_and_classification(app, engine):
    """Test that observed packets trigger device discovery and classification."""
    # Packet from PC to Router
    packet = {
        "timestamp": datetime.utcnow(),
        "src_ip": "192.168.1.100",
        "dst_ip": "192.168.1.1",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "HTTP",
        "packet_size": 500,
        "ttl": 64,  # Linux/PC ttl
        "src_mac": "00:11:22:33:44:55",
        "dst_mac": "66:77:88:99:aa:bb"
    }

    with app.app_context():
        engine.process_packet(packet)
        db.session.expire_all()

        # Check that both devices were discovered
        src_dev = Device.query.filter_by(ip_address="192.168.1.100").first()
        dst_dev = Device.query.filter_by(ip_address="192.168.1.1").first()

        assert src_dev is not None
        assert dst_dev is not None

        # Verify attributes
        assert src_dev.mac_address == "00:11:22:33:44:55"
        assert src_dev.device_type == "pc" or src_dev.device_type == "server"  # Classified based on TTL/ports
        assert dst_dev.device_type == "router"  # Ends with .1 or .254 is classified as router


def test_link_detection_and_accumulation(app, engine):
    """Test that links are recorded and traffic volume is accumulated."""
    packet = {
        "timestamp": datetime.utcnow(),
        "src_ip": "192.168.1.100",
        "dst_ip": "192.168.1.1",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "HTTP",
        "packet_size": 250,
        "ttl": 64,
        "src_mac": "00:11:22:33:44:55",
        "dst_mac": "66:77:88:99:aa:bb"
    }

    with app.app_context():
        # Process packet (devices will be registered in cache)
        engine.process_packet(packet)
        # Flush accumulated links to database immediately (simulating periodic flush)
        engine._flush_accumulated_links()
        db.session.expire_all()

        src_dev = Device.query.filter_by(ip_address="192.168.1.100").first()
        dst_dev = Device.query.filter_by(ip_address="192.168.1.1").first()

        # Query links
        link = DeviceLink.query.filter_by(
            source_device_id=src_dev.id,
            target_device_id=dst_dev.id
        ).first()

        assert link is not None
        assert link.packet_count == 1
        assert link.total_bytes == 250

        # Send another packet
        engine.process_packet(packet)
        engine._flush_accumulated_links()
        db.session.expire_all()

        link = DeviceLink.query.filter_by(
            source_device_id=src_dev.id,
            target_device_id=dst_dev.id
        ).first()
        assert link.packet_count == 2
        assert link.total_bytes == 500


def test_device_health_status_tracking(app, engine):
    """Test that device health updates to CRITICAL when active critical alerts target it."""
    packet = {
        "timestamp": datetime.utcnow(),
        "src_ip": "192.168.1.100",
        "dst_ip": "192.168.1.1",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "HTTP",
        "packet_size": 100,
        "ttl": 64,
        "src_mac": "00:11:22:33:44:55",
        "dst_mac": "66:77:88:99:aa:bb"
    }

    with app.app_context():
        # Register devices first
        engine.process_packet(packet)
        db.session.expire_all()

        dev = Device.query.filter_by(ip_address="192.168.1.100").first()
        assert dev.health_status == HealthStatus.HEALTHY

        # Create a CRITICAL alert involving this IP
        alert = Alert(
            threat_type="DDoS",
            severity=SeverityLevel.CRITICAL,
            source_ip="192.168.1.100",
            destination_ip="192.168.1.1",
            description="Simulated DDoS Attack",
            recommended_action="Block IP",
            is_resolved=False,
            timestamp=datetime.utcnow()
        )
        db.session.add(alert)
        db.session.commit()

        # Update health status
        engine._update_health_status()
        db.session.expire_all()

        # Health status of source device should be CRITICAL
        dev = Device.query.filter_by(ip_address="192.168.1.100").first()
        assert dev.health_status == HealthStatus.CRITICAL
