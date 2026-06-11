"""NetGuard AI — AI Copilot Engine.

Provides a conversational interface to the network data by detecting
user intent, querying the database for relevant context, building an
LLM prompt, and returning natural-language answers.

Supports Ollama and OpenAI backends via LangChain, with a graceful
fallback to a rule-based template assistant when no LLM is available.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from flask import Flask

from app.extensions import db
from app.models.alert import Alert, SeverityLevel
from app.models.device import Device, DeviceLink, HealthStatus
from app.models.health import HealthScore
from app.models.packet import Packet
from app.models.prediction import MLPrediction
from app.models.conversation import AIConversation, MessageRole


# ── Intent categories ─────────────────────────────────────────────────

INTENTS = [
    "system_status",
    "recent_alerts",
    "alert_detail",
    "ip_lookup",
    "traffic_stats",
    "topology_query",
    "prediction_query",
    "general",
]

# Keyword patterns mapped to intents (order matters — first match wins)
_INTENT_PATTERNS: List[tuple[str, re.Pattern]] = [
    ("alert_detail",    re.compile(r"alert\s*(?:#|id|number)?\s*(\d+)", re.I)),
    ("recent_alerts",   re.compile(r"\b(?:alerts?|threats?|incidents?|warnings?|critical)\b", re.I)),
    ("ip_lookup",       re.compile(r"\b(?:ip|address|lookup|reputation|who\s+is)\b.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I)),
    ("ip_lookup",       re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I)),
    ("traffic_stats",   re.compile(r"\b(?:traffic|bandwidth|packets?|throughput|volume|bytes?|protocols?)\b", re.I)),
    ("topology_query",  re.compile(r"\b(?:topology|devices?|routers?|switch(?:es)?|servers?|network\s*map|nodes?|links?)\b", re.I)),
    ("prediction_query", re.compile(r"\b(?:predict(?:ion)?s?|forecasts?|ml|models?|spikes?|congestion|outage|anomal(?:y|ies))\b", re.I)),
    ("system_status",   re.compile(r"\b(?:status|health|overview|summary|dashboard|how.+network)\b", re.I)),
]

# System prompt template for the LLM
_SYSTEM_PROMPT = """You are NetGuard AI Copilot, an expert Cisco network security analyst assistant.
You are embedded inside an enterprise network monitoring platform inspired by Cisco Secure Network Analytics (Stealthwatch) and Cisco XDR.

Your responsibilities:
- Analyse real-time network telemetry, alerts, and device health data.
- Explain security incidents in clear, actionable language.
- Provide Cisco-style remediation guidance referencing IOS CLI commands where appropriate.
- Present data in well-structured Markdown with tables, bullet points, and headers.

Guidelines:
- Be concise but thorough.  Use professional, security-operations language.
- When presenting numbers, use human-readable formatting (e.g. "1.2 MB" not "1234567").
- Always cite specific data from the context provided.  Do NOT fabricate statistics.
- If the context does not contain enough information, say so honestly.
"""


class AICopilotEngine:
    """Conversational AI copilot backed by an LLM (Ollama or OpenAI).

    Parameters
    ----------
    app:
        Optional Flask application.
    """

    def __init__(self, app: Optional[Flask] = None) -> None:
        self._llm_client: Optional[Any] = None
        self._app: Optional[Flask] = None

        if app is not None:
            self.init_app(app)

    # ── Flask integration ─────────────────────────────────────────────

    def init_app(self, app: Flask) -> None:
        """Bind the engine to a Flask application and configure the LLM.

        Parameters
        ----------
        app:
            The Flask application instance.
        """
        self._app = app
        app.extensions["ai_copilot"] = self
        self._init_llm_client()

    def _init_llm_client(self) -> None:
        """Initialise the LangChain LLM client based on app config."""
        if not self._app:
            return

        provider = self._app.config.get("AI_PROVIDER", "ollama").lower()

        try:
            if provider == "openai":
                api_key = self._app.config.get("OPENAI_API_KEY", "")
                model = self._app.config.get("OPENAI_MODEL", "gpt-4o-mini")
                if api_key:
                    from langchain_openai import ChatOpenAI
                    self._llm_client = ChatOpenAI(
                        model=model,
                        api_key=api_key,
                        temperature=0.3,
                        max_tokens=1024,
                    )
                    self._app.logger.info(f"AI Copilot: OpenAI client initialised (model={model})")
                else:
                    self._app.logger.warning("AI Copilot: OPENAI_API_KEY not set, falling back to rule-based assistant.")
            else:
                ollama_url = self._app.config.get("OLLAMA_URL", "http://localhost:11434")
                model = self._app.config.get("OLLAMA_MODEL", "llama3")
                from langchain_ollama import ChatOllama
                self._llm_client = ChatOllama(
                    model=model,
                    base_url=ollama_url,
                    temperature=0.3,
                    num_predict=1024,
                )
                self._app.logger.info(f"AI Copilot: Ollama client initialised (model={model}, url={ollama_url})")
        except Exception as e:
            self._app.logger.warning(f"AI Copilot: Failed to initialise LLM client: {e}. Using rule-based fallback.")
            self._llm_client = None

    # ── Public API ────────────────────────────────────────────────────

    def chat(self, session_id: str, message: str) -> str:
        """Process a user message and return the assistant's reply.

        Parameters
        ----------
        session_id:
            UUID identifying the conversation session.
        message:
            The user's chat message.

        Returns
        -------
        str
            The assistant's natural-language response.
        """
        if not self._app:
            return "Error: AI Copilot is not initialised."

        with self._app.app_context():
            # 1. Detect intent
            intent = self._detect_intent(message)

            # 2. Build database context
            context = self._build_context(message, intent)

            # 3. Try LLM, fall back to rule-based
            try:
                prompt = self._create_prompt(context, message)
                response = self._call_llm(prompt, session_id)
            except Exception as e:
                if self._app:
                    self._app.logger.warning(f"LLM call failed ({e}), using fallback assistant.")
                response = self._fallback_response(intent, context, message)

            return response

    def generate_report(self, alert_id: int) -> str:
        """Generate a detailed incident report for a given alert.

        Parameters
        ----------
        alert_id:
            Primary key of the ``Alert`` to report on.

        Returns
        -------
        str
            Markdown-formatted incident report.
        """
        if not self._app:
            return "Error: AI Copilot is not initialised."

        with self._app.app_context():
            alert = Alert.query.get(alert_id)
            if not alert:
                return f"Alert #{alert_id} not found."

            severity_str = alert.severity.value if isinstance(alert.severity, SeverityLevel) else str(alert.severity)

            # Build rich context for the report
            context = {
                "alert": alert.to_dict(),
                "related_alerts": [],
                "source_device": None,
                "destination_device": None,
            }

            # Find related alerts from the same source IP
            related = Alert.query.filter(
                Alert.source_ip == alert.source_ip,
                Alert.id != alert.id
            ).order_by(Alert.timestamp.desc()).limit(5).all()
            context["related_alerts"] = [a.to_dict() for a in related]

            # Find device records
            src_dev = Device.query.filter_by(ip_address=alert.source_ip).first()
            dst_dev = Device.query.filter_by(ip_address=alert.destination_ip).first()
            if src_dev:
                context["source_device"] = src_dev.to_dict()
            if dst_dev:
                context["destination_device"] = dst_dev.to_dict()

            # Try LLM-based report
            report_prompt = self._create_report_prompt(context)
            try:
                report = self._call_llm(report_prompt)
            except Exception:
                report = self._fallback_report(context)

            return report

    # ── Intent detection ──────────────────────────────────────────────

    def _detect_intent(self, query: str) -> str:
        """Classify the user's query into an intent category.

        Parameters
        ----------
        query:
            The user's raw message.

        Returns
        -------
        str
            Intent label (e.g. ``"alert_query"``, ``"traffic_stats"``).
        """
        for intent, pattern in _INTENT_PATTERNS:
            if pattern.search(query):
                return intent
        return "general"

    # ── Context building ──────────────────────────────────────────────

    def _build_context(self, query: str, intent: str) -> Dict[str, Any]:
        """Gather database context relevant to *query* and *intent*.

        Parameters
        ----------
        query:
            The user's raw question.
        intent:
            The classified intent string.

        Returns
        -------
        dict
            Structured context (stats, recent alerts, etc.).
        """
        context: Dict[str, Any] = {"intent": intent}
        db_data = self._query_database(intent, query)
        context.update(db_data)
        return context

    def _query_database(self, intent: str, query: str = "") -> Dict[str, Any]:
        """Execute database queries appropriate for the detected *intent*.

        Parameters
        ----------
        intent:
            The classified intent string.
        query:
            The original user query (used to extract parameters like IP addresses).

        Returns
        -------
        dict
            Query results.
        """
        data: Dict[str, Any] = {}

        if intent == "system_status":
            data.update(self._get_system_overview())

        elif intent == "recent_alerts":
            alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()
            data["recent_alerts"] = [a.to_dict() for a in alerts]
            data["total_alerts"] = Alert.query.count()
            data["unresolved_alerts"] = Alert.query.filter(Alert.is_resolved == False).count()

        elif intent == "alert_detail":
            match = re.search(r"(\d+)", query)
            if match:
                alert_id = int(match.group(1))
                alert = Alert.query.get(alert_id)
                if alert:
                    data["alert"] = alert.to_dict()
                else:
                    data["alert"] = None
                    data["error"] = f"Alert #{alert_id} not found."

        elif intent == "ip_lookup":
            ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", query)
            if ip_match:
                ip = ip_match.group(1)
                data["ip_address"] = ip

                # Device record
                dev = Device.query.filter_by(ip_address=ip).first()
                data["device"] = dev.to_dict() if dev else None

                # Alerts involving this IP
                ip_alerts = Alert.query.filter(
                    (Alert.source_ip == ip) | (Alert.destination_ip == ip)
                ).order_by(Alert.timestamp.desc()).limit(10).all()
                data["ip_alerts"] = [a.to_dict() for a in ip_alerts]

                # Packet count
                pkt_count = Packet.query.filter(
                    (Packet.src_ip == ip) | (Packet.dst_ip == ip)
                ).count()
                data["packet_count"] = pkt_count

        elif intent == "traffic_stats":
            now = datetime.utcnow()
            one_hour_ago = now - timedelta(hours=1)

            total_packets = Packet.query.filter(Packet.timestamp >= one_hour_ago).count()
            total_bytes_q = db.session.query(
                db.func.sum(Packet.packet_size)
            ).filter(Packet.timestamp >= one_hour_ago).scalar()
            total_bytes = int(total_bytes_q) if total_bytes_q else 0

            # Protocol distribution
            proto_dist = db.session.query(
                Packet.protocol, db.func.count(Packet.id)
            ).filter(Packet.timestamp >= one_hour_ago).group_by(Packet.protocol).all()

            data["traffic"] = {
                "total_packets_1h": total_packets,
                "total_bytes_1h": total_bytes,
                "protocol_distribution": {p: c for p, c in proto_dist},
            }

        elif intent == "topology_query":
            devices = Device.query.all()
            links = DeviceLink.query.all()
            data["devices"] = [d.to_dict() for d in devices]
            data["links"] = [l.to_dict() for l in links]
            data["device_count"] = len(devices)
            data["link_count"] = len(links)

        elif intent == "prediction_query":
            preds = MLPrediction.query.order_by(MLPrediction.created_at.desc()).limit(10).all()
            data["predictions"] = [p.to_dict() for p in preds]

        else:  # general — provide a broad summary
            data.update(self._get_system_overview())

        return data

    def _get_system_overview(self) -> Dict[str, Any]:
        """Gather a comprehensive system overview for the copilot."""
        now = datetime.utcnow()
        one_hour_ago = now - timedelta(hours=1)

        # Alerts summary
        total_alerts = Alert.query.count()
        unresolved = Alert.query.filter(Alert.is_resolved == False).count()
        critical = Alert.query.filter(
            Alert.severity == SeverityLevel.CRITICAL,
            Alert.is_resolved == False
        ).count()

        # Device summary
        total_devices = Device.query.count()
        healthy_devices = Device.query.filter(Device.health_status == HealthStatus.HEALTHY).count()
        critical_devices = Device.query.filter(Device.health_status == HealthStatus.CRITICAL).count()

        # Traffic summary (last hour)
        total_packets = Packet.query.filter(Packet.timestamp >= one_hour_ago).count()
        total_bytes_q = db.session.query(
            db.func.sum(Packet.packet_size)
        ).filter(Packet.timestamp >= one_hour_ago).scalar()
        total_bytes = int(total_bytes_q) if total_bytes_q else 0

        # Latest health score
        latest_health = HealthScore.query.order_by(HealthScore.created_at.desc()).first()

        return {
            "system_overview": {
                "total_alerts": total_alerts,
                "unresolved_alerts": unresolved,
                "critical_alerts": critical,
                "total_devices": total_devices,
                "healthy_devices": healthy_devices,
                "critical_devices": critical_devices,
                "packets_last_hour": total_packets,
                "bytes_last_hour": total_bytes,
                "latest_health": latest_health.to_dict() if latest_health else None,
            }
        }

    # ── Prompt construction ───────────────────────────────────────────

    def _create_prompt(self, context: Dict[str, Any], query: str) -> str:
        """Assemble the final LLM prompt from context and user query.

        Parameters
        ----------
        context:
            Structured context dictionary.
        query:
            The user's original question.

        Returns
        -------
        str
            The complete prompt string.
        """
        context_text = self._format_context(context)

        return f"""{_SYSTEM_PROMPT}

--- REAL-TIME NETWORK CONTEXT ---
{context_text}
--- END CONTEXT ---

User Question: {query}

Provide a clear, professional response based on the data above."""

    def _create_report_prompt(self, context: Dict[str, Any]) -> str:
        """Assemble the incident report prompt."""
        alert = context.get("alert", {})
        related = context.get("related_alerts", [])
        src_dev = context.get("source_device")
        dst_dev = context.get("destination_device")

        related_text = ""
        if related:
            related_text = "\n".join(
                f"  - [{a.get('severity')}] {a.get('threat_type')} at {a.get('timestamp')}"
                for a in related
            )
        else:
            related_text = "  None found."

        src_text = f"  Type: {src_dev.get('device_type')}, Health: {src_dev.get('health_status')}, Vendor: {src_dev.get('vendor')}" if src_dev else "  No device record found."
        dst_text = f"  Type: {dst_dev.get('device_type')}, Health: {dst_dev.get('health_status')}, Vendor: {dst_dev.get('vendor')}" if dst_dev else "  No device record found."

        return f"""{_SYSTEM_PROMPT}

Generate a detailed incident report in Markdown format for the following alert:

Alert ID: {alert.get('id')}
Threat Type: {alert.get('threat_type')}
Severity: {alert.get('severity')}
Source IP: {alert.get('source_ip')}
Destination IP: {alert.get('destination_ip')}
Timestamp: {alert.get('timestamp')}
Description: {alert.get('description')}
Evidence: {alert.get('raw_evidence', 'N/A')}
Recommended Action: {alert.get('recommended_action')}
Resolved: {alert.get('is_resolved')}

Related Alerts from Source IP:
{related_text}

Source Device Info:
{src_text}

Destination Device Info:
{dst_text}

Structure the report with these sections:
1. Executive Summary
2. Threat Analysis
3. Impact Assessment
4. Root Cause Analysis
5. Remediation Steps (including Cisco IOS commands where applicable)
6. Preventive Measures"""

    def _format_context(self, context: Dict[str, Any]) -> str:
        """Convert structured context dict into human-readable text for the LLM."""
        lines: List[str] = []
        intent = context.get("intent", "general")

        if "system_overview" in context:
            ov = context["system_overview"]
            lines.append("## System Overview")
            lines.append(f"- Total Alerts: {ov.get('total_alerts', 0)}")
            lines.append(f"- Unresolved Alerts: {ov.get('unresolved_alerts', 0)}")
            lines.append(f"- Critical Alerts: {ov.get('critical_alerts', 0)}")
            lines.append(f"- Total Devices: {ov.get('total_devices', 0)}")
            lines.append(f"- Healthy Devices: {ov.get('healthy_devices', 0)}")
            lines.append(f"- Critical Devices: {ov.get('critical_devices', 0)}")
            lines.append(f"- Packets (last hour): {ov.get('packets_last_hour', 0)}")
            bytes_val = ov.get('bytes_last_hour', 0)
            lines.append(f"- Traffic (last hour): {self._format_bytes(bytes_val)}")
            health = ov.get("latest_health")
            if health:
                lines.append(f"- Network Health Score: {health.get('overall_score', 'N/A')}/100 ({health.get('status', 'UNKNOWN')})")

        if "recent_alerts" in context:
            lines.append("\n## Recent Alerts")
            for a in context["recent_alerts"][:10]:
                sev = a.get("severity", "?")
                lines.append(f"- [{sev}] {a.get('threat_type')} | Src: {a.get('source_ip')} -> Dst: {a.get('destination_ip')} | {a.get('timestamp', '')}")

        if "alert" in context and context["alert"]:
            a = context["alert"]
            lines.append("\n## Alert Detail")
            lines.append(f"- ID: {a.get('id')}")
            lines.append(f"- Threat: {a.get('threat_type')}")
            lines.append(f"- Severity: {a.get('severity')}")
            lines.append(f"- Source: {a.get('source_ip')} -> {a.get('destination_ip')}")
            lines.append(f"- Description: {a.get('description')}")
            lines.append(f"- Recommended Action: {a.get('recommended_action')}")
            lines.append(f"- Resolved: {a.get('is_resolved')}")

        if "ip_address" in context:
            ip = context["ip_address"]
            lines.append(f"\n## IP Lookup: {ip}")
            dev = context.get("device")
            if dev:
                lines.append(f"- Device Type: {dev.get('device_type')}")
                lines.append(f"- Hostname: {dev.get('hostname')}")
                lines.append(f"- Health: {dev.get('health_status')}")
                lines.append(f"- Vendor: {dev.get('vendor')}")
                lines.append(f"- OS: {dev.get('os_guess')}")
            else:
                lines.append("- No device record found in the inventory.")
            lines.append(f"- Total Packets: {context.get('packet_count', 0)}")
            ip_alerts = context.get("ip_alerts", [])
            if ip_alerts:
                lines.append(f"- Alerts involving this IP ({len(ip_alerts)}):")
                for a in ip_alerts[:5]:
                    lines.append(f"  - [{a.get('severity')}] {a.get('threat_type')} ({a.get('timestamp')})")

        if "traffic" in context:
            t = context["traffic"]
            lines.append("\n## Traffic Statistics (Last Hour)")
            lines.append(f"- Total Packets: {t.get('total_packets_1h', 0):,}")
            lines.append(f"- Total Traffic: {self._format_bytes(t.get('total_bytes_1h', 0))}")
            proto = t.get("protocol_distribution", {})
            if proto:
                lines.append("- Protocol Distribution:")
                for p, c in sorted(proto.items(), key=lambda x: x[1], reverse=True):
                    lines.append(f"  - {p}: {c:,} packets")

        if "devices" in context:
            lines.append(f"\n## Network Topology ({context.get('device_count', 0)} devices, {context.get('link_count', 0)} links)")
            for d in context.get("devices", [])[:15]:
                status = d.get("health_status", "UNKNOWN")
                lines.append(f"- {d.get('hostname', d.get('ip_address'))} ({d.get('device_type')}) [{status}] - {d.get('ip_address')}")

        if "predictions" in context:
            lines.append("\n## ML Predictions")
            for p in context.get("predictions", [])[:5]:
                lines.append(f"- [{p.get('prediction_type')}] {p.get('model_name')}: {p.get('prediction_data')} (confidence: {p.get('confidence', 0):.2f})")

        return "\n".join(lines) if lines else "No relevant data found in the database."

    @staticmethod
    def _format_bytes(num_bytes: int) -> str:
        """Format byte count to human-readable string."""
        if num_bytes < 1024:
            return f"{num_bytes} B"
        elif num_bytes < 1024 * 1024:
            return f"{num_bytes / 1024:.1f} KB"
        elif num_bytes < 1024 * 1024 * 1024:
            return f"{num_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{num_bytes / (1024 * 1024 * 1024):.2f} GB"

    # ── LLM interaction ───────────────────────────────────────────────

    def _call_llm(self, prompt: str, session_id: str = "") -> str:
        """Send *prompt* to the configured LLM and return the response.

        Parameters
        ----------
        prompt:
            The full prompt text.
        session_id:
            Optional session ID (used for conversation history context).

        Returns
        -------
        str
            The LLM's response text.

        Raises
        ------
        RuntimeError
            If no LLM client is available.
        """
        if self._llm_client is None:
            raise RuntimeError("No LLM client available.")

        from langchain_core.messages import HumanMessage, SystemMessage

        messages = [
            SystemMessage(content=_SYSTEM_PROMPT),
            HumanMessage(content=prompt),
        ]

        response = self._llm_client.invoke(messages)
        return response.content

    # ── Fallback rule-based assistant ─────────────────────────────────

    def _fallback_response(self, intent: str, context: Dict[str, Any], query: str) -> str:
        """Generate a structured response without an LLM using templates.

        This serves as the primary response engine in local/demo mode
        when no LLM provider is configured.
        """
        if intent == "system_status":
            return self._fb_system_status(context)
        elif intent == "recent_alerts":
            return self._fb_recent_alerts(context)
        elif intent == "alert_detail":
            return self._fb_alert_detail(context)
        elif intent == "ip_lookup":
            return self._fb_ip_lookup(context)
        elif intent == "traffic_stats":
            return self._fb_traffic_stats(context)
        elif intent == "topology_query":
            return self._fb_topology(context)
        elif intent == "prediction_query":
            return self._fb_predictions(context)
        else:
            return self._fb_general(context, query)

    def _fb_system_status(self, ctx: Dict[str, Any]) -> str:
        ov = ctx.get("system_overview", {})
        health = ov.get("latest_health")
        health_line = f"**Network Health Score:** {health.get('overall_score', 'N/A')}/100 ({health.get('status', 'UNKNOWN')})" if health else "**Network Health Score:** No data available."

        return f"""## Network Status Overview

{health_line}

| Metric | Value |
|---|---|
| Total Alerts | {ov.get('total_alerts', 0)} |
| Unresolved Alerts | {ov.get('unresolved_alerts', 0)} |
| Critical Alerts | {ov.get('critical_alerts', 0)} |
| Total Devices | {ov.get('total_devices', 0)} |
| Healthy Devices | {ov.get('healthy_devices', 0)} |
| Critical Devices | {ov.get('critical_devices', 0)} |
| Packets (1h) | {ov.get('packets_last_hour', 0):,} |
| Traffic (1h) | {self._format_bytes(ov.get('bytes_last_hour', 0))} |

{'**Action Required:** There are ' + str(ov.get('critical_alerts', 0)) + ' critical unresolved alerts requiring immediate attention.' if ov.get('critical_alerts', 0) > 0 else 'All systems are operating normally.'}"""

    def _fb_recent_alerts(self, ctx: Dict[str, Any]) -> str:
        alerts = ctx.get("recent_alerts", [])
        total = ctx.get("total_alerts", 0)
        unresolved = ctx.get("unresolved_alerts", 0)

        if not alerts:
            return "No alerts found in the system. The network appears to be operating normally."

        rows = []
        for a in alerts[:10]:
            sev = a.get("severity", "?")
            rows.append(f"| {a.get('id')} | {sev} | {a.get('threat_type')} | {a.get('source_ip')} | {a.get('destination_ip')} | {'Yes' if a.get('is_resolved') else 'No'} |")

        table = "\n".join(rows)
        return f"""## Recent Security Alerts

**Total:** {total} | **Unresolved:** {unresolved}

| ID | Severity | Threat | Source | Destination | Resolved |
|---|---|---|---|---|---|
{table}

**Recommendation:** Prioritise investigating CRITICAL and HIGH severity alerts. Use `show ip access-lists` on affected Cisco devices to verify existing ACL protections."""

    def _fb_alert_detail(self, ctx: Dict[str, Any]) -> str:
        alert = ctx.get("alert")
        if not alert:
            return ctx.get("error", "Alert not found.")

        return f"""## Alert #{alert.get('id')} - {alert.get('threat_type')}

| Field | Value |
|---|---|
| Severity | **{alert.get('severity')}** |
| Source IP | {alert.get('source_ip')} |
| Destination IP | {alert.get('destination_ip')} |
| Timestamp | {alert.get('timestamp')} |
| Resolved | {'Yes' if alert.get('is_resolved') else 'No'} |

### Description
{alert.get('description')}

### Evidence
{alert.get('raw_evidence', 'No raw evidence available.')}

### Recommended Action
{alert.get('recommended_action')}

### Cisco IOS Mitigation
To block the source IP on a Cisco router:
```
conf t
ip access-list extended BLOCK-THREAT
 deny ip host {alert.get('source_ip')} any
 permit ip any any
exit
interface GigabitEthernet0/0
 ip access-group BLOCK-THREAT in
end
write memory
```"""

    def _fb_ip_lookup(self, ctx: Dict[str, Any]) -> str:
        ip = ctx.get("ip_address", "Unknown")
        dev = ctx.get("device")
        pkt_count = ctx.get("packet_count", 0)
        ip_alerts = ctx.get("ip_alerts", [])

        dev_section = "No device record found in the inventory."
        if dev:
            dev_section = f"""| Field | Value |
|---|---|
| Hostname | {dev.get('hostname', 'N/A')} |
| Type | {dev.get('device_type')} |
| Health | {dev.get('health_status')} |
| Vendor | {dev.get('vendor', 'N/A')} |
| OS | {dev.get('os_guess', 'N/A')} |
| MAC | {dev.get('mac_address', 'N/A')} |"""

        alert_section = "No alerts involving this IP."
        if ip_alerts:
            rows = "\n".join(
                f"| {a.get('severity')} | {a.get('threat_type')} | {a.get('timestamp')} |"
                for a in ip_alerts[:5]
            )
            alert_section = f"""| Severity | Threat | Time |
|---|---|---|
{rows}"""

        return f"""## IP Lookup: {ip}

### Device Information
{dev_section}

### Traffic
- Total Packets: {pkt_count:,}

### Associated Alerts
{alert_section}"""

    def _fb_traffic_stats(self, ctx: Dict[str, Any]) -> str:
        t = ctx.get("traffic", {})
        proto = t.get("protocol_distribution", {})

        proto_rows = "\n".join(
            f"| {p} | {c:,} |"
            for p, c in sorted(proto.items(), key=lambda x: x[1], reverse=True)
        ) if proto else "| No data | - |"

        return f"""## Traffic Statistics (Last Hour)

| Metric | Value |
|---|---|
| Total Packets | {t.get('total_packets_1h', 0):,} |
| Total Traffic | {self._format_bytes(t.get('total_bytes_1h', 0))} |

### Protocol Distribution
| Protocol | Packets |
|---|---|
{proto_rows}"""

    def _fb_topology(self, ctx: Dict[str, Any]) -> str:
        devices = ctx.get("devices", [])
        count = ctx.get("device_count", 0)
        links = ctx.get("link_count", 0)

        if not devices:
            return "No devices discovered in the network topology."

        rows = "\n".join(
            f"| {d.get('hostname', d.get('ip_address'))} | {d.get('ip_address')} | {d.get('device_type')} | {d.get('health_status', 'UNKNOWN')} |"
            for d in devices[:15]
        )

        return f"""## Network Topology

**Discovered:** {count} devices, {links} links

| Hostname | IP Address | Type | Health |
|---|---|---|---|
{rows}"""

    def _fb_predictions(self, ctx: Dict[str, Any]) -> str:
        preds = ctx.get("predictions", [])
        if not preds:
            return "No ML predictions available. Train models first using the `/api/v1/ml/train` endpoint."

        rows = "\n".join(
            f"| {p.get('model_name')} | {p.get('prediction_type')} | {p.get('confidence', 0):.2f} | {p.get('prediction_for', 'N/A')} |"
            for p in preds[:5]
        )

        return f"""## ML Predictions

| Model | Type | Confidence | Prediction For |
|---|---|---|---|
{rows}

*Use the prediction data to proactively address potential network issues before they escalate.*"""

    def _fb_general(self, ctx: Dict[str, Any], query: str) -> str:
        """General fallback that provides the system overview."""
        overview = self._fb_system_status(ctx)
        return f"""{overview}

---

*I can help you with:*
- **"Show recent alerts"** - View security alerts
- **"What is the status of IP 10.0.0.1?"** - IP lookup and reputation
- **"Show traffic statistics"** - Network traffic analysis
- **"Show network topology"** - Device inventory and links
- **"Show predictions"** - ML-based forecasts
- **"Alert #5"** - Detailed alert investigation"""

    # ── Fallback report ───────────────────────────────────────────────

    def _fallback_report(self, context: Dict[str, Any]) -> str:
        """Generate a structured incident report without an LLM."""
        alert = context.get("alert", {})
        related = context.get("related_alerts", [])
        src_dev = context.get("source_device")
        dst_dev = context.get("destination_device")

        severity = alert.get("severity", "UNKNOWN")
        threat = alert.get("threat_type", "Unknown Threat")

        related_text = "No related alerts found."
        if related:
            related_text = "\n".join(
                f"- [{a.get('severity')}] {a.get('threat_type')} at {a.get('timestamp')}"
                for a in related
            )

        src_text = f"Type: {src_dev.get('device_type')}, Health: {src_dev.get('health_status')}, Vendor: {src_dev.get('vendor')}" if src_dev else "No device record found."
        dst_text = f"Type: {dst_dev.get('device_type')}, Health: {dst_dev.get('health_status')}, Vendor: {dst_dev.get('vendor')}" if dst_dev else "No device record found."

        return f"""# Incident Report - Alert #{alert.get('id')}

## 1. Executive Summary

A **{severity}** severity **{threat}** event was detected originating from `{alert.get('source_ip')}` targeting `{alert.get('destination_ip')}` at {alert.get('timestamp')}.

{alert.get('description', 'No description available.')}

## 2. Threat Analysis

- **Threat Type:** {threat}
- **Severity:** {severity}
- **Source IP:** {alert.get('source_ip')}
- **Destination IP:** {alert.get('destination_ip')}
- **Evidence:** {alert.get('raw_evidence', 'N/A')}

### Related Activity from Source IP
{related_text}

## 3. Impact Assessment

- **Source Device:** {src_text}
- **Destination Device:** {dst_text}
- **Potential Impact:** {'Critical infrastructure at risk. Immediate response required.' if severity == 'CRITICAL' else 'Moderate risk. Investigation recommended.' if severity == 'HIGH' else 'Low risk. Monitor and review.'}

## 4. Root Cause Analysis

Based on the threat type **{threat}**, the likely root cause is {'a coordinated attack or compromised host generating excessive traffic.' if 'DDoS' in threat or 'Flood' in threat else 'reconnaissance activity probing for open ports and vulnerable services.' if 'Scan' in threat else 'repeated authentication failures suggesting credential stuffing or brute force attempts.' if 'Brute' in threat else 'suspicious network activity requiring further investigation.'}

## 5. Remediation Steps

{alert.get('recommended_action', 'Review and apply appropriate security controls.')}

### Cisco IOS Commands
```
! Block source IP
conf t
ip access-list extended INCIDENT-{alert.get('id')}-BLOCK
 deny ip host {alert.get('source_ip')} any log
 permit ip any any
exit
interface GigabitEthernet0/0
 ip access-group INCIDENT-{alert.get('id')}-BLOCK in
end
write memory

! Verify
show ip access-lists INCIDENT-{alert.get('id')}-BLOCK
show logging | include {alert.get('source_ip')}
```

## 6. Preventive Measures

- Enable NetFlow monitoring on edge interfaces: `ip flow-export destination <collector> 9996`
- Configure CoPP (Control Plane Policing) to rate-limit suspicious traffic
- Deploy Cisco Umbrella for DNS-layer protection
- Review and harden ACLs on perimeter devices
- Schedule regular vulnerability assessments using Cisco Secure Network Analytics
"""
