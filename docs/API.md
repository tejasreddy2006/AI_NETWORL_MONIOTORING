# NetGuard AI - API Documentation

## Overview
The backend provides a comprehensive REST API (`/api/v1`) and a real-time WebSocket interface using Socket.IO.

## REST API Endpoints

### 1. Packets & Traffic
- `GET /api/v1/packets` - List packets (paginated, filterable by IP/Protocol)
- `GET /api/v1/packets/stats` - Traffic statistics (bytes/packets over time)
- `GET /api/v1/packets/protocols` - Protocol distribution (TCP/UDP/ICMP breakdown)
- `GET /api/v1/packets/timeline` - Time-series traffic data

### 2. Alerts & Threats
- `GET /api/v1/alerts` - List generated security alerts
- `GET /api/v1/alerts/<id>` - Get alert details and evidence
- `PUT /api/v1/alerts/<id>/resolve` - Mark an alert as resolved

### 3. Network Topology
- `GET /api/v1/topology/devices` - List all discovered devices and health status
- `GET /api/v1/topology/links` - List traffic links between devices
- `GET /api/v1/topology/graph` - Get combined nodes/edges for React Flow

### 4. Machine Learning & AI
- `GET /api/v1/ml/predictions` - View ML forecasted anomalies and spikes
- `POST /api/v1/ml/train` - Manually trigger ML model training
- `POST /api/v1/ai/chat` - Send a message to the AI Copilot (`{ "session_id": "...", "message": "..." }`)

### 5. Threat Intelligence
- `GET /api/v1/threatintel/map` - Geographic distribution of suspicious traffic
- `GET /api/v1/threatintel/lookup/<ip>` - Get reputation and location for an IP

### 6. System Health & Simulation
- `GET /api/v1/health/score` - Current composite network health score (0-100)
- `GET /api/v1/health/history` - Historical health scores
- `POST /api/v1/simulation/run` - Trigger attack simulation (`{ "scenario_type": "port_scan", "config": {...} }`)

---

## WebSocket Events (Socket.IO)
Connect to the root endpoint `/` via Socket.IO client.

### Client Receives (Backend -> Frontend)
- `packet:new` - Emitted when a new packet is captured and analyzed.
- `alert:new` - Emitted immediately when the Threat Detection Engine raises an alert.
- `health:update` - Periodic update of the global health score.
- `topology:update` - Emitted when a new device or link is discovered.
- `ai:response` - Emitted in response to an async AI query.

### Client Sends (Frontend -> Backend)
- `ai:query` - Send a chat message asynchronously (`{ "session_id": "...", "message": "..." }`)
