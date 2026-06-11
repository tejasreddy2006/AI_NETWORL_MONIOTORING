# NetGuard AI 🛡️

NetGuard AI is an enterprise-grade, AI-powered network security and monitoring platform inspired by Cisco Secure Network Analytics (Stealthwatch). It provides real-time traffic analysis, automated threat detection, predictive machine learning forecasts, and a conversational AI Copilot for network engineers.

## Features

- **Real-Time Packet Capture:** Low-level packet sniffing using `scapy` with high-throughput batching and ring-buffer architecture.
- **Threat Detection Engine:** Stateful, rule-based detection for DDoS attacks, Port Scans, ICMP Floods, and Brute Force attempts.
- **Network Topology Discovery:** Passive device fingerprinting and link mapping visualized using React Flow.
- **Predictive Analytics (ML):** `scikit-learn` integration for bandwidth forecasting, congestion prediction, and anomaly detection (Isolation Forest & Random Forest).
- **AI Copilot (RAG):** Natural language interface using LangChain (Ollama/OpenAI) to query real-time network telemetry and generate Cisco IOS mitigation commands.
- **Enterprise Dashboard:** Dark-mode, responsive React SPA built with Vite, TailwindCSS, and Recharts, utilizing Socket.IO for live streaming updates.

## Architecture

- **Frontend:** React 18, Vite, TailwindCSS v4, React Router DOM, Recharts, React Flow, Leaflet.
- **Backend:** Python, Flask, Flask-SocketIO (Eventlet), SQLAlchemy, Scapy, Scikit-Learn, LangChain.
- **Database:** MySQL (Production) / SQLite (Development).
- **Caching/PubSub:** Redis.
- **Deployment:** Docker & Docker Compose.

## Getting Started

Please see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for detailed instructions on running the application locally or via Docker Compose.

## Documentation

- [API Reference](docs/API.md) - REST and WebSocket documentation.
- [Architecture Details](docs/ARCHITECTURE.md) - Deep dive into the 8 backend engines.
- [Interview Q&A](docs/INTERVIEW_QA.md) - Talking points for technical interviews.

## License

MIT License. See `LICENSE` for details.
