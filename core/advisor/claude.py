"""
SecureBridge — LLM Threat Advisor
Claude API integration for intelligent OT security analysis

Transforms raw anomaly data into actionable intelligence:
- Plain-English threat explanation
- Root cause analysis with likelihood ranking
- IEC 62443-aligned response actions
- Escalation recommendations
"""

import os
import sys
import json
import logging
import anthropic
from datetime import datetime

sys.path.insert(0, os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
))

logger = logging.getLogger("SecureBridge.Advisor")


# ─────────────────────────────────────────────────────────
# OT Security Context for LLM
# ─────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an expert OT/ICS Cybersecurity Analyst 
with 20 years of experience in critical infrastructure security, 
including oil & gas, manufacturing, and industrial instrumentation.

You specialize in:
- Modbus TCP protocol security
- IEC 62443 industrial cybersecurity framework
- Purdue Model for ICS security architecture
- OT threat intelligence (Dragos, Claroty methodologies)
- Real-world ICS incident response

When analyzing anomalies, you provide:
1. Clear, non-technical explanations for management
2. Technical root cause analysis for security engineers
3. Specific, actionable response steps
4. Regulatory compliance references (IEC 62443)

You always prioritize operational continuity — in OT environments,
Availability comes before Confidentiality."""


ANALYSIS_PROMPT = """Analyze this OT/ICS security anomaly and provide 
a structured assessment.

ANOMALY DATA:
- Device: {device_id}
- Protocol: {protocol}
- Event Type: {event_type}
- Anomaly Score: {anomaly_score}/100
- Severity: {severity}
- Source IP: {src_ip}
- Destination IP: {dst_ip}
- Function Code: {function_code} ({function_name})
- Register Address: {register_address}
- Is Write Operation: {is_write}
- Timestamp: {timestamp}
- Additional Context: {context}

Respond ONLY with valid JSON in this exact format:
{{
  "threat_summary": "One sentence — what happened in plain English",
  "threat_detail": "2-3 sentences — technical explanation for security team",
  "possible_causes": [
    {{"rank": 1, "cause": "description", "likelihood": "65%", "type": "malicious/operational/technical"}},
    {{"rank": 2, "cause": "description", "likelihood": "25%", "type": "malicious/operational/technical"}},
    {{"rank": 3, "cause": "description", "likelihood": "10%", "type": "malicious/operational/technical"}}
  ],
  "immediate_actions": [
    "Action 1 — specific and actionable",
    "Action 2 — specific and actionable",
    "Action 3 — specific and actionable"
  ],
  "iec62443_reference": {{
    "requirement": "SR X.X",
    "title": "Requirement title",
    "description": "How this anomaly relates to this requirement"
  }},
  "operational_impact": "low/medium/high/critical",
  "data_integrity_risk": true/false,
  "escalate_immediately": true/false,
  "escalation_reason": "Why escalation is or is not needed",
  "mitre_attack_ics": "Relevant MITRE ATT&CK for ICS technique if applicable, or null",
  "analyst_notes": "Additional context or recommendations"
}}"""


# ─────────────────────────────────────────────────────────
# Threat Advisor
# ─────────────────────────────────────────────────────────

class ThreatAdvisor:
    """
    LLM-powered OT threat analysis
    Provides intelligent context around anomaly detections
    """

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            logger.warning(
                "ANTHROPIC_API_KEY not set. "
                "Set environment variable or pass api_key parameter."
            )
        self.client = None
        self._init_client()
        self._cache = {}  # Simple cache for repeated patterns

    def _init_client(self):
        if self.api_key:
            self.client = anthropic.Anthropic(api_key=self.api_key)
            logger.info("LLM Advisor initialized — Claude API connected")

    def analyze(self, anomaly: dict) -> dict:
        """
        Analyze an OT anomaly using Claude

        Args:
            anomaly: dict with event data + anomaly scores

        Returns:
            dict with complete threat analysis
        """
        if not self.client:
            return self._fallback_analysis(anomaly)

        # Build prompt
        prompt = ANALYSIS_PROMPT.format(
            device_id=anomaly.get("device_id", "Unknown"),
            protocol=anomaly.get("protocol", "Modbus TCP"),
            event_type=anomaly.get("event_type", "Unknown"),
            anomaly_score=anomaly.get("anomaly_score", 0),
            severity=anomaly.get("severity", "UNKNOWN"),
            src_ip=anomaly.get("src_ip", "Unknown"),
            dst_ip=anomaly.get("dst_ip", "Unknown"),
            function_code=anomaly.get("function_code", ""),
            function_name=anomaly.get("function_name", ""),
            register_address=anomaly.get("register_address", ""),
            is_write=anomaly.get("is_write", False),
            timestamp=anomaly.get("timestamp", datetime.now().isoformat()),
            context=self._build_context(anomaly)
        )

        try:
            response = self.client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=1500,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}]
            )

            raw = response.content[0].text.strip()

            # Clean JSON if wrapped in code blocks
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]

            analysis = json.loads(raw)
            analysis["analyzed_at"] = datetime.now().isoformat()
            analysis["model"] = "claude-sonnet-4-6"
            analysis["success"] = True

            logger.info(
                f"Analysis complete: {anomaly.get('device_id')} | "
                f"Score: {anomaly.get('anomaly_score')} | "
                f"Escalate: {analysis.get('escalate_immediately')}"
            )

            return analysis

        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            return self._fallback_analysis(anomaly)
        except Exception as e:
            logger.error(f"LLM analysis error: {e}")
            return self._fallback_analysis(anomaly)

    def _build_context(self, anomaly: dict) -> str:
        """Build additional context for better LLM analysis"""
        ctx = []

        score = anomaly.get("anomaly_score", 0)
        if score >= 80:
            ctx.append("VERY HIGH anomaly score — significant deviation from baseline")
        elif score >= 65:
            ctx.append("HIGH anomaly score — notable deviation from normal behavior")

        if anomaly.get("is_write"):
            ctx.append("WRITE OPERATION — potential unauthorized command to OT device")

        fc = anomaly.get("function_code")
        if fc == 43:
            ctx.append("DISCOVERY SCAN — device identification attempt")
        elif fc in [15, 16]:
            ctx.append("MULTIPLE WRITE — bulk register modification")

        reg = anomaly.get("register_address", 0)
        if isinstance(reg, (int, float)) and reg > 45000:
            ctx.append("UNUSUAL register address — outside normal operational range")

        src = anomaly.get("src_ip", "")
        dst = anomaly.get("dst_ip", "")
        if src and dst and src.split(".")[2] != dst.split(".")[2]:
            ctx.append("CROSS-SUBNET — traffic crossing network boundaries")

        return "; ".join(ctx) if ctx else "Standard OT event"

    def _fallback_analysis(self, anomaly: dict) -> dict:
        """Rule-based fallback when LLM unavailable"""
        severity = anomaly.get("severity", "MEDIUM")
        score = anomaly.get("anomaly_score", 0)
        is_write = anomaly.get("is_write", False)

        if is_write:
            summary = (
                f"Unauthorized write command detected on "
                f"{anomaly.get('device_id', 'OT device')} — "
                f"immediate investigation required"
            )
            actions = [
                "Immediately identify source of write command",
                "Verify if change was authorized via change management",
                "Check OT device for unexpected configuration changes",
                "Review network logs for source IP activity"
            ]
            iec_req = "SR 2.1 — Authorization Enforcement"
            escalate = True
        elif score >= 70:
            summary = (
                f"High anomaly score on {anomaly.get('device_id', 'OT device')} "
                f"— behavioral deviation detected"
            )
            actions = [
                "Investigate source IP for unauthorized access",
                "Review network traffic logs around this timestamp",
                "Verify OT device is operating normally",
                "Check for any recent network changes"
            ]
            iec_req = "SR 6.2 — Continuous Monitoring"
            escalate = score >= 80
        else:
            summary = (
                f"Moderate anomaly on {anomaly.get('device_id', 'OT device')} "
                f"— monitor and investigate"
            )
            actions = [
                "Monitor device for continued anomalous behavior",
                "Review operational logs for context",
                "Verify normal operational activity"
            ]
            iec_req = "SR 6.2 — Continuous Monitoring"
            escalate = False

        return {
            "threat_summary": summary,
            "threat_detail": (
                f"Anomaly score of {score}/100 detected on "
                f"{anomaly.get('protocol', 'OT protocol')} traffic. "
                f"Rule-based analysis applied (LLM unavailable)."
            ),
            "possible_causes": [
                {
                    "rank": 1,
                    "cause": "Unauthorized network access attempt",
                    "likelihood": "40%",
                    "type": "malicious"
                },
                {
                    "rank": 2,
                    "cause": "Misconfigured automation or SCADA system",
                    "likelihood": "35%",
                    "type": "operational"
                },
                {
                    "rank": 3,
                    "cause": "Network or hardware fault",
                    "likelihood": "25%",
                    "type": "technical"
                }
            ],
            "immediate_actions": actions,
            "iec62443_reference": {
                "requirement": iec_req.split(" — ")[0],
                "title": iec_req.split(" — ")[1] if " — " in iec_req else "",
                "description": "Manual investigation required"
            },
            "operational_impact": (
                "high" if score >= 70 else "medium"
            ),
            "data_integrity_risk": is_write,
            "escalate_immediately": escalate,
            "escalation_reason": (
                "High anomaly score requires immediate human review"
                if escalate else "Monitor and review"
            ),
            "mitre_attack_ics": None,
            "analyst_notes": "Fallback analysis — configure ANTHROPIC_API_KEY for full LLM analysis",
            "analyzed_at": datetime.now().isoformat(),
            "model": "rule-based-fallback",
            "success": True
        }

    def format_alert_message(self, anomaly: dict, analysis: dict) -> str:
        """Format alert for notification channels"""
        severity = anomaly.get("severity", "UNKNOWN")
        score = anomaly.get("anomaly_score", 0)
        device = anomaly.get("device_id", "Unknown")
        timestamp = anomaly.get("timestamp", "")

        emoji = {
            "CRITICAL": "🚨",
            "HIGH": "⚠️",
            "MEDIUM": "🔔",
            "LOW": "ℹ️"
        }.get(severity, "❓")

        lines = [
            f"{emoji} SECUREBRIDGE ALERT — {severity}",
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            f"Device: {device}",
            f"Score: {score}/100",
            f"Time: {timestamp}",
            f"",
            f"📋 WHAT HAPPENED:",
            f"{analysis.get('threat_summary', 'Analysis unavailable')}",
            f"",
            f"⚡ IMMEDIATE ACTIONS:",
        ]

        for i, action in enumerate(
            analysis.get("immediate_actions", [])[:3], 1
        ):
            lines.append(f"{i}. {action}")

        iec = analysis.get("iec62443_reference", {})
        if iec:
            lines.extend([
                f"",
                f"📖 IEC 62443: {iec.get('requirement')} — {iec.get('title')}",
            ])

        if analysis.get("escalate_immediately"):
            lines.extend([
                f"",
                f"🔺 ESCALATE TO HUMAN ANALYST IMMEDIATELY",
                f"Reason: {analysis.get('escalation_reason', '')}",
            ])

        return "\n".join(lines)


# ─────────────────────────────────────────────────────────
# CLI Test
# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    test_anomaly = {
        "device_id": "PLC-01",
        "protocol": "Modbus TCP",
        "event_type": "MODBUS_WRITE",
        "anomaly_score": 87.5,
        "severity": "CRITICAL",
        "src_ip": "192.168.10.199",
        "dst_ip": "192.168.40.10",
        "function_code": 6,
        "function_name": "Write Single Register",
        "register_address": 40001,
        "is_write": True,
        "timestamp": datetime.now().isoformat(),
    }

    advisor = ThreatAdvisor()
    print("\nAnalyzing anomaly...")
    analysis = advisor.analyze(test_anomaly)
    alert = advisor.format_alert_message(test_anomaly, analysis)
    print("\n" + alert)
    print("\n--- Full Analysis ---")
    print(json.dumps(analysis, indent=2))
