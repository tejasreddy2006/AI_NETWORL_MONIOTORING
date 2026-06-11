"""NetGuard AI — AI Copilot Engine Tests.

Tests intent detection, context building, fallback responses, and report generation.
"""

import pytest
from datetime import datetime
from app import create_app
from app.extensions import db
from app.models.alert import Alert, SeverityLevel
from app.models.device import Device, HealthStatus
from app.models.packet import Packet
from app.engines.ai_copilot import AICopilotEngine


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
    """Create an AICopilotEngine instance (no LLM client — tests fallback path)."""
    eng = AICopilotEngine(app)
    eng._llm_client = None  # Force fallback mode
    return eng


@pytest.fixture
def seeded_db(app):
    """Seed the database with sample data for context queries."""
    with app.app_context():
        # Create devices
        dev1 = Device(
            ip_address="192.168.1.1",
            mac_address="00:11:22:33:44:55",
            device_type="router",
            hostname="core-router-1",
            vendor="Cisco",
            os_guess="Cisco IOS",
            health_status=HealthStatus.HEALTHY,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        dev2 = Device(
            ip_address="10.0.0.5",
            mac_address="aa:bb:cc:dd:ee:ff",
            device_type="server",
            hostname="web-server-1",
            vendor="Linux",
            os_guess="Ubuntu 22.04",
            health_status=HealthStatus.CRITICAL,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        db.session.add_all([dev1, dev2])

        # Create alerts
        alert1 = Alert(
            timestamp=datetime.utcnow(),
            threat_type="Port Scan",
            severity=SeverityLevel.HIGH,
            source_ip="45.33.32.156",
            destination_ip="192.168.1.1",
            description="Detected rapid sequential port probing.",
            raw_evidence="SYN packets to ports 22,80,443,3306,8080",
            recommended_action="Block source IP and investigate.",
            is_resolved=False,
        )
        alert2 = Alert(
            timestamp=datetime.utcnow(),
            threat_type="DDoS",
            severity=SeverityLevel.CRITICAL,
            source_ip="10.0.0.99",
            destination_ip="10.0.0.5",
            description="Volumetric DDoS attack detected.",
            recommended_action="Enable rate limiting.",
            is_resolved=False,
        )
        db.session.add_all([alert1, alert2])

        # Create packets
        for i in range(20):
            pkt = Packet(
                timestamp=datetime.utcnow(),
                src_ip="192.168.1.1",
                dst_ip="10.0.0.5",
                src_port=54321,
                dst_port=80,
                protocol="TCP" if i % 2 == 0 else "UDP",
                packet_size=500 + i * 10,
                ttl=64,
            )
            db.session.add(pkt)

        db.session.commit()


# ── Intent Detection Tests ────────────────────────────────────────────

class TestIntentDetection:
    """Test the keyword-based intent classifier."""

    def test_system_status_intent(self, engine):
        assert engine._detect_intent("What is the network status?") == "system_status"
        assert engine._detect_intent("Show me the health overview") == "system_status"

    def test_recent_alerts_intent(self, engine):
        assert engine._detect_intent("Show recent alerts") == "recent_alerts"
        assert engine._detect_intent("Any critical threats?") == "recent_alerts"

    def test_alert_detail_intent(self, engine):
        assert engine._detect_intent("Tell me about alert #5") == "alert_detail"
        assert engine._detect_intent("Alert ID 12") == "alert_detail"

    def test_ip_lookup_intent(self, engine):
        assert engine._detect_intent("Who is 10.0.0.1?") == "ip_lookup"
        assert engine._detect_intent("Lookup IP 192.168.1.100") == "ip_lookup"

    def test_traffic_stats_intent(self, engine):
        assert engine._detect_intent("Show traffic statistics") == "traffic_stats"
        assert engine._detect_intent("How much bandwidth are we using?") == "traffic_stats"

    def test_topology_intent(self, engine):
        assert engine._detect_intent("Show network topology") == "topology_query"
        assert engine._detect_intent("List all devices") == "topology_query"

    def test_prediction_intent(self, engine):
        assert engine._detect_intent("Show ML predictions") == "prediction_query"
        assert engine._detect_intent("Any anomaly detected?") == "prediction_query"

    def test_general_intent(self, engine):
        assert engine._detect_intent("Hello, how are you?") == "general"


# ── Context Building Tests ────────────────────────────────────────────

class TestContextBuilding:
    """Test that context queries retrieve real DB data."""

    def test_system_overview_context(self, app, engine, seeded_db):
        with app.app_context():
            ctx = engine._build_context("status", "system_status")
            assert "system_overview" in ctx
            overview = ctx["system_overview"]
            assert overview["total_alerts"] == 2
            assert overview["unresolved_alerts"] == 2
            assert overview["total_devices"] == 2

    def test_recent_alerts_context(self, app, engine, seeded_db):
        with app.app_context():
            ctx = engine._build_context("alerts", "recent_alerts")
            assert "recent_alerts" in ctx
            assert len(ctx["recent_alerts"]) == 2
            assert ctx["total_alerts"] == 2

    def test_ip_lookup_context(self, app, engine, seeded_db):
        with app.app_context():
            data = engine._query_database("ip_lookup", "Tell me about 192.168.1.1")
            assert data["ip_address"] == "192.168.1.1"
            assert data["device"] is not None
            assert data["device"]["hostname"] == "core-router-1"
            assert data["packet_count"] == 20

    def test_traffic_context(self, app, engine, seeded_db):
        with app.app_context():
            data = engine._query_database("traffic_stats")
            assert "traffic" in data
            assert data["traffic"]["total_packets_1h"] == 20

    def test_topology_context(self, app, engine, seeded_db):
        with app.app_context():
            data = engine._query_database("topology_query")
            assert data["device_count"] == 2


# ── Fallback Response Tests ───────────────────────────────────────────

class TestFallbackResponses:
    """Test that the rule-based fallback generates structured Markdown responses."""

    def test_chat_returns_markdown(self, app, engine, seeded_db):
        with app.app_context():
            response = engine.chat("test-session", "Show network status")
            assert "## Network Status Overview" in response
            assert "Total Alerts" in response

    def test_alert_chat(self, app, engine, seeded_db):
        with app.app_context():
            response = engine.chat("test-session", "Show recent alerts")
            assert "Security Alerts" in response
            assert "Port Scan" in response

    def test_ip_lookup_chat(self, app, engine, seeded_db):
        with app.app_context():
            response = engine.chat("test-session", "Who is 192.168.1.1?")
            assert "192.168.1.1" in response
            assert "core-router-1" in response

    def test_traffic_chat(self, app, engine, seeded_db):
        with app.app_context():
            response = engine.chat("test-session", "Show traffic stats")
            assert "Traffic Statistics" in response

    def test_general_chat(self, app, engine, seeded_db):
        with app.app_context():
            response = engine.chat("test-session", "Hello there")
            assert "Network Status Overview" in response
            assert "I can help you with" in response


# ── Report Generation Tests ───────────────────────────────────────────

class TestReportGeneration:
    """Test the incident report generation path."""

    def test_report_for_existing_alert(self, app, engine, seeded_db):
        with app.app_context():
            alert = Alert.query.first()
            report = engine.generate_report(alert.id)
            assert "Incident Report" in report
            assert "Executive Summary" in report
            assert "Threat Analysis" in report
            assert "Remediation Steps" in report
            assert alert.source_ip in report

    def test_report_for_missing_alert(self, app, engine, seeded_db):
        with app.app_context():
            report = engine.generate_report(99999)
            assert "not found" in report
