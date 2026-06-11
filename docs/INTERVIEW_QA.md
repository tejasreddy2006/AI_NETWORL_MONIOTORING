# NetGuard AI - Interview Q&A Guide

If you are asked about this project in a job interview (especially for Network Security, DevNet, or Full-Stack roles), here are talking points to highlight your architectural decisions.

### 1. What was the most challenging technical aspect of this project?
**Answer:** "The most challenging part was bridging the gap between low-level network packet capture and high-level web interfaces in real-time. I had to use Python's `scapy` to sniff packets at the interface level, parse them efficiently without blocking the main thread, and push aggregated metrics over a WebSocket via `Flask-SocketIO`. To prevent the UI from being overwhelmed by thousands of packets per second, I implemented a ring-buffer and batching mechanism in the backend."

### 2. How did you handle Threat Detection?
**Answer:** "I built a modular, rule-based Threat Detection Engine. Instead of just relying on simple thresholds, the engine maintains a stateful connection tracker (`_connection_tracker`). For example, to detect a DDoS or ICMP Flood, it calculates packet rates over a sliding window. To detect port scans, it tracks the number of unique destination ports targeted by a single source IP within a short timeframe. When thresholds are breached, it generates a normalized `Alert` object."

### 3. Explain the Machine Learning Prediction architecture.
**Answer:** "I implemented a predictive analytics layer using `scikit-learn`. The system periodically extracts historical traffic volume and alert frequency from the database, transforming it into a structured pandas DataFrame. I trained an Isolation Forest for anomaly detection (spikes/outages) and a Random Forest for congestion prediction. The models are serialized using `joblib` so they don't have to be retrained on every restart, but I also built a self-healing fallback that automatically generates synthetic training data if the historical database is too sparse upon initial deployment."

### 4. How did you integrate GenAI/LLMs into a network tool?
**Answer:** "I integrated a Retrieval-Augmented Generation (RAG) system using LangChain. Network data is inherently structured (SQL tables), so I built an Intent Classifier that parses the user's natural language query (e.g., 'Show me recent threats from 10.0.0.1') using Regex. It then dynamically queries the relevant SQLAlchemy models (Alerts, Packets, Devices), formats the output into readable Markdown, and injects it into a Cisco-specific System Prompt. This is then sent to an LLM (either local Ollama or OpenAI) to generate actionable remediation steps."

### 5. Why did you choose React/Vite over a traditional templating engine like Jinja2?
**Answer:** "Real-time network telemetry requires dynamic, non-blocking UI updates. A traditional server-rendered architecture would require constant polling or full page reloads, which is inefficient. By decoupling the frontend into a React SPA built with Vite, I could maintain a persistent WebSocket connection for live traffic charts (using Recharts) and dynamic topology mapping (using React Flow), resulting in a much smoother, enterprise-grade user experience similar to Cisco Stealthwatch."

### 6. How is the application deployed?
**Answer:** "The application is containerized using Docker. I wrote a `docker-compose.yml` that orchestrates four services: an Nginx reverse proxy, the Flask backend running under Gunicorn (with Eventlet for async WebSocket support), a MySQL production database, and a Redis instance for caching and message brokering. This ensures the environment is reproducible and scalable."
