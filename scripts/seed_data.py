#!/usr/bin/env python3
"""
Seed the NetGuard AI database with realistic demo data.

Generates:
  - 500 sample network packets
  - 20 security alerts (using SeverityLevel enum)
  - 10 network devices with links (using HealthStatus enum)
  - 24 hours of health scores (using NetworkStatus enum)
  - 15 countries of geo traffic
  - 5 ML predictions and registered models
  - 2 AI conversation log messages

Usage:
    python scripts/seed_data.py [--force]
"""

import sys
import os
import random
from datetime import datetime, timedelta

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app import create_app, db
from app.models.packet import Packet
from app.models.alert import Alert, SeverityLevel
from app.models.device import Device, DeviceLink, HealthStatus
from app.models.health import HealthScore, NetworkStatus
from app.models.geo_traffic import GeoTraffic
from app.models.prediction import MLPrediction, MLModel
from app.models.conversation import AIConversation, MessageRole
from app.models.simulation import SimulationResult

# ──────────────────────────────────────────────
# Data Constants
# ──────────────────────────────────────────────

INTERNAL_IPS = [
    '192.168.1.1', '192.168.1.10', '192.168.1.20', '192.168.1.30',
    '192.168.1.50', '192.168.1.100', '192.168.1.150', '192.168.1.200',
    '192.168.2.1', '192.168.2.10', '192.168.2.50',
    '10.0.0.1', '10.0.0.5', '10.0.0.10', '10.0.0.50',
    '10.0.1.1', '10.0.1.10', '10.0.1.100',
]

EXTERNAL_IPS = [
    '8.8.8.8', '8.8.4.4', '1.1.1.1', '208.67.222.222',
    '151.101.1.140', '13.107.42.14', '172.217.14.206',
    '31.13.65.36', '52.96.108.170', '104.244.42.193',
    '185.199.108.153', '140.82.121.3', '199.232.69.194',
    '93.184.216.34', '23.185.0.2', '54.239.28.85',
    '45.33.32.156', '91.189.88.181', '203.0.113.50',
    '198.51.100.25', '178.62.55.100', '185.70.41.35',
]

PROTOCOLS = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'ICMP', 'FTP', 'SMTP', 'ARP']

PROTOCOL_PORTS = {
    'TCP': [80, 443, 8080, 8443, 3000, 5000, 3306, 6379],
    'UDP': [53, 123, 161, 500, 5060],
    'HTTP': [80, 8080, 8000],
    'HTTPS': [443, 8443],
    'DNS': [53],
    'SSH': [22],
    'ICMP': [0],
    'FTP': [21, 20],
    'SMTP': [25, 587],
    'ARP': [0],
}

ALERT_TYPES = [
    ('DDoS Attack Detected', 'critical', 'ddos',
     'High volume of SYN packets detected from multiple sources targeting port 80. Rate exceeds 10,000 packets/sec threshold.'),
    ('Port Scan Detected', 'high', 'port_scan',
     'Sequential port scanning detected from {src_ip}. Over 100 ports probed in 30 seconds.'),
    ('Suspicious DNS Query', 'medium', 'dns_anomaly',
     'Unusual DNS query pattern detected. Possible DNS tunneling or data exfiltration via encoded subdomains to {dst_ip}.'),
    ('Brute Force Attempt', 'high', 'brute_force',
     'Multiple failed SSH login attempts from {src_ip}. 15 failed attempts in 2 minutes on port 22.'),
    ('Malware Communication', 'critical', 'malware',
     'Outbound connection to known C2 server {dst_ip} detected. Traffic pattern matches known malware signature.'),
    ('Data Exfiltration', 'critical', 'exfiltration',
     'Abnormal data transfer volume detected. {src_ip} sent 2.3GB to external IP {dst_ip} outside business hours.'),
    ('ARP Spoofing', 'high', 'arp_spoof',
     'ARP reply conflict detected. MAC address for {src_ip} changed unexpectedly. Possible man-in-the-middle attack.'),
    ('Unauthorized Access', 'medium', 'unauthorized',
     'Access attempt to restricted subnet 10.0.1.0/24 from {src_ip}. Source is not in authorized ACL.'),
    ('SSL Certificate Anomaly', 'low', 'ssl_anomaly',
     'Self-signed certificate detected on connection to {dst_ip}:443. Certificate CN does not match hostname.'),
    ('Unusual Traffic Spike', 'medium', 'traffic_spike',
     'Network traffic increased by 340% compared to baseline. Spike concentrated on ports 443 and 8080.'),
]

DEVICE_DEFINITIONS = [
    ('core-router-01', 'router', '192.168.1.1', 'Cisco ISR 4321', 'online'),
    ('edge-router-02', 'router', '192.168.2.1', 'Cisco ISR 4431', 'online'),
    ('switch-core-01', 'switch', '192.168.1.2', 'Cisco Catalyst 9300', 'online'),
    ('switch-access-01', 'switch', '192.168.1.3', 'Cisco Catalyst 9200', 'online'),
    ('web-server-01', 'server', '192.168.1.10', 'Ubuntu 22.04 LTS', 'online'),
    ('db-server-01', 'server', '192.168.1.20', 'CentOS 8 / MySQL', 'online'),
    ('app-server-01', 'server', '192.168.1.30', 'Ubuntu 22.04 / Docker', 'warning'),
    ('workstation-01', 'pc', '192.168.1.100', 'Windows 11 Pro', 'online'),
    ('workstation-02', 'pc', '192.168.1.150', 'macOS Ventura', 'offline'),
    ('iot-sensor-01', 'iot', '192.168.1.200', 'Raspberry Pi 4', 'online'),
]

DEVICE_LINKS = [
    ('core-router-01', 'switch-core-01'),
    ('core-router-01', 'edge-router-02'),
    ('switch-core-01', 'switch-access-01'),
    ('switch-core-01', 'web-server-01'),
    ('switch-core-01', 'db-server-01'),
    ('switch-core-01', 'app-server-01'),
    ('switch-access-01', 'workstation-01'),
    ('switch-access-01', 'workstation-02'),
    ('switch-access-01', 'iot-sensor-01'),
    ('edge-router-02', 'switch-access-01'),
]

GEO_COUNTRIES = [
    ('United States', 'US', 37.0902, -95.7129),
    ('China', 'CN', 35.8617, 104.1954),
    ('Russia', 'RU', 61.5240, 105.3188),
    ('Germany', 'DE', 51.1657, 10.4515),
    ('United Kingdom', 'GB', 55.3781, -3.4360),
    ('India', 'IN', 20.5937, 78.9629),
    ('Brazil', 'BR', -14.2350, -51.9253),
    ('Japan', 'JP', 36.2048, 138.2529),
    ('France', 'FR', 46.2276, 2.2137),
    ('Canada', 'CA', 56.1304, -106.3468),
    ('Australia', 'AU', -25.2744, 133.7751),
    ('South Korea', 'KR', 35.9078, 127.7669),
    ('Netherlands', 'NL', 52.1326, 5.2913),
    ('Singapore', 'SG', 1.3521, 103.8198),
    ('Ukraine', 'UA', 48.3794, 31.1656),
]


def generate_mac():
    """Generate a random MAC address."""
    return ':'.join([f'{random.randint(0, 255):02x}' for _ in range(6)])


def seed_packets(count=500):
    """Generate sample network packets."""
    now = datetime.utcnow()
    packets = []

    for _ in range(count):
        protocol = random.choice(PROTOCOLS)
        is_external = random.random() < 0.4

        if is_external:
            src_ip = random.choice(INTERNAL_IPS) if random.random() < 0.6 else random.choice(EXTERNAL_IPS)
            dst_ip = random.choice(EXTERNAL_IPS) if src_ip in INTERNAL_IPS else random.choice(INTERNAL_IPS)
        else:
            src_ip = random.choice(INTERNAL_IPS)
            dst_ip = random.choice(INTERNAL_IPS)
            while dst_ip == src_ip:
                dst_ip = random.choice(INTERNAL_IPS)

        ports = PROTOCOL_PORTS.get(protocol, [80])
        dst_port = random.choice(ports)
        src_port = random.randint(1024, 65535)

        # Vary packet sizes by protocol
        if protocol in ('ICMP', 'ARP', 'DNS'):
            length = random.randint(28, 256)
        elif protocol in ('HTTP', 'HTTPS'):
            length = random.randint(200, 15000)
        elif protocol == 'FTP':
            length = random.randint(64, 5000)
        else:
            length = random.randint(40, 1500)

        # Spread timestamps over last 24 hours
        timestamp = now - timedelta(
            hours=random.uniform(0, 24),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59)
        )

        packet = Packet(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_size=length,
            ttl=random.choice([64, 128, 54, 255]),
            src_mac=generate_mac(),
            dst_mac=generate_mac(),
            payload_preview=f'{protocol} {src_ip}:{src_port} → {dst_ip}:{dst_port} length={length}',
            created_at=timestamp
        )
        packets.append(packet)

    db.session.bulk_save_objects(packets)
    db.session.commit()
    return len(packets)


def seed_alerts(count=20):
    """Generate sample security alerts."""
    now = datetime.utcnow()
    alerts = []

    severity_mapping = {
        'low': SeverityLevel.LOW,
        'medium': SeverityLevel.MEDIUM,
        'high': SeverityLevel.HIGH,
        'critical': SeverityLevel.CRITICAL
    }

    for _ in range(count):
        template = random.choice(ALERT_TYPES)
        threat_type_name, severity_str, alert_type, desc_template = template

        src_ip = random.choice(EXTERNAL_IPS)
        dst_ip = random.choice(INTERNAL_IPS)

        description = desc_template.format(src_ip=src_ip, dst_ip=dst_ip)

        timestamp = now - timedelta(
            hours=random.uniform(0, 48),
            minutes=random.randint(0, 59)
        )

        is_resolved = random.random() < 0.3
        resolved_at = timestamp + timedelta(hours=random.uniform(0.5, 4)) if is_resolved else None

        alert = Alert(
            timestamp=timestamp,
            threat_type=threat_type_name,
            severity=severity_mapping.get(severity_str, SeverityLevel.LOW),
            source_ip=src_ip,
            destination_ip=dst_ip,
            description=description,
            raw_evidence=f"Flow details: {src_ip} -> {dst_ip} pattern matches threshold criteria for {alert_type}.",
            recommended_action=f"Filter source IP {src_ip} at network edge; execute credentials audit on target {dst_ip}.",
            is_resolved=is_resolved,
            resolved_at=resolved_at,
            resolved_by='secops_bot' if is_resolved else None,
            created_at=timestamp
        )
        alerts.append(alert)

    db.session.bulk_save_objects(alerts)
    db.session.commit()
    return len(alerts)


def seed_devices():
    """Generate network devices and links."""
    devices = {}

    status_mapping = {
        'online': HealthStatus.HEALTHY,
        'warning': HealthStatus.WARNING,
        'offline': HealthStatus.CRITICAL
    }

    for name, dev_type, ip, model, status in DEVICE_DEFINITIONS:
        vendor = 'Cisco' if 'Cisco' in model else ('Ubuntu' if 'Ubuntu' in model else ('CentOS' if 'CentOS' in model else 'Apple' if 'mac' in model.lower() else 'Raspberry Pi'))
        device = Device(
            ip_address=ip,
            mac_address=generate_mac(),
            device_type=dev_type,
            hostname=name,
            vendor=vendor,
            os_guess=model,
            health_status=status_mapping.get(status, HealthStatus.UNKNOWN),
            first_seen=datetime.utcnow() - timedelta(days=5),
            last_seen=datetime.utcnow() - timedelta(minutes=random.randint(0, 30)),
            created_at=datetime.utcnow() - timedelta(days=5)
        )
        db.session.add(device)
        db.session.flush()  # Acquire ID
        devices[name] = device

    # Create links
    links_created = 0
    for src_name, dst_name in DEVICE_LINKS:
        if src_name in devices and dst_name in devices:
            link = DeviceLink(
                source_device_id=devices[src_name].id,
                target_device_id=devices[dst_name].id,
                packet_count=random.randint(1000, 100000),
                total_bytes=random.randint(50000, 200000000),
                first_seen=datetime.utcnow() - timedelta(days=5),
                last_seen=datetime.utcnow()
            )
            db.session.add(link)
            links_created += 1

    db.session.commit()
    return len(devices), links_created


def seed_health_scores(hours=24):
    """Generate hourly health scores for the last N hours."""
    now = datetime.utcnow()
    scores = []
    base_score = 85

    for h in range(hours):
        timestamp = now - timedelta(hours=hours - h)

        variation = random.uniform(-8, 5)
        if 8 <= h <= 12:
            variation -= random.uniform(5, 15)  # dip during "incident" period

        overall = max(0, min(100, base_score + variation))

        if overall >= 80:
            status = NetworkStatus.EXCELLENT
        elif overall >= 60:
            status = NetworkStatus.GOOD
        elif overall >= 40:
            status = NetworkStatus.WARNING
        else:
            status = NetworkStatus.CRITICAL

        score = HealthScore(
            overall_score=round(overall, 1),
            traffic_stability=round(max(0, min(100, overall + random.uniform(-5, 5))), 1),
            device_availability=round(max(0, min(100, overall + random.uniform(-2, 4))), 1),
            alert_frequency=round(max(0, min(100, 100 - random.uniform(0, 40))), 1),
            bandwidth_usage=round(random.uniform(30, 85), 1),
            packet_loss=round(random.uniform(0, 1.8), 2),
            status=status,
            created_at=timestamp
        )
        scores.append(score)

    db.session.bulk_save_objects(scores)
    db.session.commit()
    return len(scores)


def seed_geo_traffic():
    """Generate geographic traffic data."""
    entries = []

    for country, code, lat, lon in GEO_COUNTRIES:
        total_bytes = random.randint(500000, 100000000)
        reputation = random.uniform(85, 99)
        if code in ('RU', 'CN', 'UA'):
            reputation = random.uniform(30, 75)

        entry = GeoTraffic(
            ip_address=random.choice(EXTERNAL_IPS),
            country_code=code,
            country_name=country,
            city="Core City",
            latitude=lat,
            longitude=lon,
            packet_count=random.randint(500, 20000),
            total_bytes=total_bytes,
            reputation_score=round(reputation, 1),
            last_seen=datetime.utcnow() - timedelta(minutes=random.randint(0, 120)),
            created_at=datetime.utcnow() - timedelta(days=2)
        )
        entries.append(entry)

    db.session.bulk_save_objects(entries)
    db.session.commit()
    return len(entries)


def seed_ml_predictions():
    """Generate sample ML predictions and register models."""
    # Seed Models first
    models = [
        MLModel(
            model_name="BandwidthForecastModel",
            algorithm="Random Forest Regressor",
            metrics={"r2_score": 0.89, "mae": 15.4},
            model_path="./ml_models/bandwidth_rf.pkl",
            training_samples=1500,
            trained_at=datetime.utcnow() - timedelta(days=1)
        ),
        MLModel(
            model_name="CongestionForecastModel",
            algorithm="Gradient Boosting Classifier",
            metrics={"accuracy": 0.94, "f1_score": 0.92},
            model_path="./ml_models/congestion_gb.pkl",
            training_samples=2200,
            trained_at=datetime.utcnow() - timedelta(days=1)
        )
    ]
    for model in models:
        db.session.add(model)
    db.session.flush()

    # Seed Predictions
    predictions = [
        MLPrediction(
            model_name="BandwidthForecastModel",
            prediction_type="traffic_forecast",
            prediction_data={
                "predicted_bandwidth_mbps": 450.5,
                "current_bandwidth_mbps": 220.1,
                "spike_likelihood": 0.82
            },
            confidence=0.88,
            prediction_for=datetime.utcnow() + timedelta(hours=3),
            created_at=datetime.utcnow()
        ),
        MLPrediction(
            model_name="CongestionForecastModel",
            prediction_type="congestion_prediction",
            prediction_data={
                "congested_ports": [443, 8080],
                "expected_queue_delay_ms": 120,
                "congestion_level": "medium"
            },
            confidence=0.91,
            prediction_for=datetime.utcnow() + timedelta(hours=1),
            created_at=datetime.utcnow()
        )
    ]
    for pred in predictions:
        db.session.add(pred)

    db.session.commit()
    return len(models), len(predictions)


def seed_conversations():
    """Seed sample conversation logs."""
    session_id = "demo-session-uuid-1234"
    msgs = [
        AIConversation(
            session_id=session_id,
            role=MessageRole.user,
            content="Are there any critical threats active on our network?",
            context_used=None,
            created_at=datetime.utcnow() - timedelta(minutes=5)
        ),
        AIConversation(
            session_id=session_id,
            role=MessageRole.assistant,
            content="I found 3 medium severity alerts, but no critical security threats are currently active. Overall network health is Excellent (91%).",
            context_used={"active_alerts": 3, "health_score": 91.0},
            created_at=datetime.utcnow() - timedelta(minutes=4)
        )
    ]
    for msg in msgs:
        db.session.add(msg)
    db.session.commit()
    return len(msgs)


def main():
    """Run all seed functions."""
    # Check for non-interactive flag --force
    force = '--force' in sys.argv or '-y' in sys.argv

    app = create_app()

    with app.app_context():
        print("=" * 60)
        print("[SEED] Seeding NetGuard AI Database")
        print("=" * 60)

        # Check if data already exists
        existing = Packet.query.first()
        if existing:
            if not force:
                confirm = input("WARNING: Data already exists. Clear and reseed? (y/N): ")
                if confirm.lower() != 'y':
                    print("Aborted.")
                    return
            
            print("Clearing existing data...")
            SimulationResult.query.delete()
            AIConversation.query.delete()
            MLPrediction.query.delete()
            MLModel.query.delete()
            GeoTraffic.query.delete()
            HealthScore.query.delete()
            DeviceLink.query.delete()
            Device.query.delete()
            Alert.query.delete()
            Packet.query.delete()
            db.session.commit()

        print()
        packet_count = seed_packets(500)
        print(f"  Packets:          {packet_count}")

        alert_count = seed_alerts(20)
        print(f"  Alerts:           {alert_count}")

        device_count, link_count = seed_devices()
        print(f"  Devices:          {device_count}")
        print(f"  Device Links:     {link_count}")

        health_count = seed_health_scores(24)
        print(f"  Health Scores:    {health_count}")

        geo_count = seed_geo_traffic()
        print(f"  Geo Traffic:      {geo_count}")

        model_count, ml_count = seed_ml_predictions()
        print(f"  ML Models Reg:    {model_count}")
        print(f"  ML Predictions:   {ml_count}")

        convo_count = seed_conversations()
        print(f"  AI Conversations: {convo_count}")

        print()
        print("=" * 60)
        print("[OK] Database seeded successfully!")
        print("=" * 60)


if __name__ == '__main__':
    main()
