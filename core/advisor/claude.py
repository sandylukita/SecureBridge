"""
SecureBridge — Hybrid LLM Threat Advisor
=========================================
Provides intelligent OT/ICS threat analysis with two backends:

  Claude API   (cloud)    — highest quality reasoning, CRITICAL alerts
  Ollama local (on-prem)  — air-gapped environments, zero data egress

Backend selection is controlled by config.llm.mode:

  auto       — CRITICAL severity → Claude; routine → Ollama if available
  claude     — Always Claude API (requires ANTHROPIC_API_KEY)
  ollama     — Always local Ollama (air-gapped / offline)
  air-gapped — Alias for ollama; makes intent explicit in YAML config

Both backends use the identical prompt schema and return the same JSON
structure — the dashboard and alerting layer never need to know which
backend was used. A model/mode field in the response identifies the source.

Output schema (identical across all backends):
  threat_summary       : plain-English one-liner for management
  threat_detail        : technical explanation for security team
  possible_causes      : ranked list with likelihood %
  immediate_actions    : specific, ordered response steps
  iec62443_reference   : SR requirement + title + description
  operational_impact   : low / medium / high / critical
  data_integrity_risk  : bool
  escalate_immediately : bool
  escalation_reason    : string
  mitre_attack_ics     : MITRE ATT&CK for ICS technique or null
  analyst_notes        : additional context
  model                : which backend/model was used
  mode                 : cloud / air-gapped-local / rule-based
  success              : bool
"""

import os
import sys
import json
import logging
import anthropic
from datetime import datetime

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

sys.path.insert(0, os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
))

logger = logging.getLogger("SecureBridge.Advisor")


# ─────────────────────────────────────────────────────────
# Shared Prompt Templates
# (identical for Claude and Ollama — consistent output)
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
Availability comes before Confidentiality.

CRITICAL CONSTRAINT — MITRE ATT&CK Framework:
You MUST use ONLY the MITRE ATT&CK for ICS matrix when referencing
attack techniques. ICS techniques use the T0xxx format (four-digit code
prefixed with T0), for example:
  T0836 — Modify Parameter
  T0855 — Unauthorized Command Message
  T0814 — Denial of Control
  T0846 — Remote System Discovery
  T0843 — Program Upload
  T0817 — Drive-by Compromise
NEVER use Enterprise ATT&CK tactic codes (TAxxx format) or Enterprise
technique codes (Txxxx four-digit without leading zero). The domains are
distinct: ICS ATT&CK covers OT/SCADA/ICS environments exclusively."""


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
  "data_integrity_risk": true,
  "escalate_immediately": true,
  "escalation_reason": "Why escalation is or is not needed",
  "analyst_notes": "Additional context or recommendations"
}}"""


def _clean_json(raw: str) -> dict:
    """
    Parse JSON from LLM response, handling code block wrappers.
    Both Claude and Ollama occasionally wrap output in ```json ... ```.
    """
    text = raw.strip()
    if text.startswith("```"):
        parts = text.split("```")
        # parts[1] is the content between first pair of backticks
        content = parts[1] if len(parts) > 1 else text
        if content.startswith("json"):
            content = content[4:]
        text = content.strip()
    return json.loads(text)


def _build_context(anomaly: dict) -> str:
    """Build additional context string for richer LLM analysis."""
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
        ctx.append("DISCOVERY SCAN — device identification attempt (recon signature)")
    elif fc in [15, 16]:
        ctx.append("MULTIPLE WRITE — bulk register modification")

    # Flag anomaly flags from feature engineering (v2)
    flags = anomaly.get("flags", {})
    if flags.get("unknown_source_ip"):
        ctx.append(f"UNKNOWN SOURCE IP: {flags['unknown_source_ip']}")
    if flags.get("packet_burst"):
        ctx.append(f"BURST DETECTED: {flags['packet_burst']}")

    reg = anomaly.get("register_address", 0)
    if isinstance(reg, (int, float)) and reg > 45000:
        ctx.append("UNUSUAL register address — outside normal operational range")

    src = anomaly.get("src_ip", "")
    dst = anomaly.get("dst_ip", "")
    try:
        if src and dst and src.split(".")[2] != dst.split(".")[2]:
            ctx.append("CROSS-SUBNET — traffic crossing network boundaries")
    except IndexError:
        pass

    return "; ".join(ctx) if ctx else "Standard OT event"


def _build_prompt(anomaly: dict) -> str:
    """Render ANALYSIS_PROMPT with anomaly data."""
    return ANALYSIS_PROMPT.format(
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
        context=_build_context(anomaly),
    )


# ─────────────────────────────────────────────────────────
# Claude Backend
# ─────────────────────────────────────────────────────────

class ClaudeBackend:
    """
    Anthropic Claude API backend.
    Requires ANTHROPIC_API_KEY environment variable.
    Provides highest-quality threat reasoning for complex incidents.
    """

    def __init__(self, model: str = "claude-sonnet-4-6", max_tokens: int = 1500):
        self.model      = model
        self.max_tokens = max_tokens
        self.client     = None
        self.available  = False
        self._init()

    def _init(self):
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            logger.warning(
                "ANTHROPIC_API_KEY not set — Claude backend unavailable. "
                "Set env var or use ollama/air-gapped mode."
            )
            return
        try:
            self.client    = anthropic.Anthropic(api_key=api_key, max_retries=0)
            self.available = True
            logger.info(f"Claude backend ready — model: {self.model}")
        except Exception as exc:
            logger.warning(f"Claude init failed: {exc}")

    def analyze(self, anomaly: dict) -> dict:
        if not self.client:
            raise RuntimeError("Claude client not initialized")

        prompt   = _build_prompt(anomaly)
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        raw      = response.content[0].text
        analysis = _clean_json(raw)
        analysis["model"] = f"claude/{self.model}"
        analysis["mode"]  = "cloud"
        return analysis


# ─────────────────────────────────────────────────────────
# Gemini Backend
# ─────────────────────────────────────────────────────────

class GeminiBackend:
    """
    Google Gemini API backend.
    Requires GEMINI_API_KEY environment variable.
    Free tier support (15 RPM free) & sub-second inference.
    Ideal for cloud showcase & demo labs without heavy GPU/RAM cost.
    """

    def __init__(self, model: str = "gemini-flash-latest"):
        self.model     = model
        self.client    = None
        self.available = False
        self._init()

    def _init(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            logger.warning(
                "GEMINI_API_KEY not set — Gemini backend unavailable. "
                "Set GEMINI_API_KEY env var for free-tier cloud LLM mode."
            )
            return
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            self.client = genai.GenerativeModel(
                model_name=self.model,
                system_instruction=SYSTEM_PROMPT
            )
            self.available = True
            logger.info(f"Gemini backend ready — model: {self.model}")
        except Exception as exc:
            logger.warning(f"Gemini init failed: {exc}")

    def analyze(self, anomaly: dict) -> dict:
        if not self.client:
            raise RuntimeError("Gemini client not initialized")

        prompt = _build_prompt(anomaly)
        generation_config = {"response_mime_type": "application/json"}
        
        from google.api_core import retry
        # Disable retry so Streamlit doesn't hang indefinitely on 429 errors
        response = self.client.generate_content(
            prompt,
            generation_config=generation_config,
            request_options={"retry": retry.Retry(initial=0, maximum=0, timeout=10.0)}
        )
        raw = response.text
        analysis = _clean_json(raw)
        analysis["model"] = f"gemini/{self.model}"
        analysis["mode"]  = "cloud-free-tier"
        return analysis


# ─────────────────────────────────────────────────────────
# Ollama Backend
# ─────────────────────────────────────────────────────────

class OllamaBackend:
    """
    Local Ollama backend — air-gapped / offline mode.

    Zero data egress: all inference runs on the local machine.
    Recommended models (in order of JSON output quality):
      qwen2.5:14b  — best structured JSON, needs ~10GB RAM
      llama3.1:8b  — good balance, needs ~6GB RAM
      llama3.1     — default tag (usually 8b)
      mistral:7b   — fast, decent quality

    Sandy's 32GB RAM can comfortably run qwen2.5:14b.
    """

    def __init__(
        self,
        model: str = "llama3.1",
        host: str = "http://localhost:11434",
    ):
        self.model     = model
        self.host      = host
        self.client    = None
        self.available = False
        self._init()

    def _init(self):
        try:
            import ollama as _ollama
            # Override host if non-default
            if self.host != "http://localhost:11434":
                self.client = _ollama.Client(host=self.host)
            else:
                self.client = _ollama
            # Quick connectivity check — list models
            models = self.client.list()
            available_tags = [m.model for m in models.models]
            logger.info(
                f"Ollama backend ready — host: {self.host} | "
                f"model: {self.model} | "
                f"available models: {available_tags}"
            )
            # Warn if requested model not pulled yet
            if not any(self.model in tag for tag in available_tags):
                logger.warning(
                    f"Model '{self.model}' not found in Ollama. "
                    f"Run: ollama pull {self.model}"
                )
            self.available = True
        except ImportError:
            logger.warning(
                "ollama package not installed — run: pip install ollama"
            )
        except Exception as exc:
            logger.warning(
                f"Ollama unavailable ({type(exc).__name__}: {exc}). "
                f"Is Ollama running? Start with: ollama serve"
            )

    def analyze(self, anomaly: dict) -> dict:
        if not self.client:
            raise RuntimeError("Ollama client not initialized")

        # Combine system + user prompt (Ollama supports system role)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": _build_prompt(anomaly)},
        ]

        try:
            # format='json' enforces JSON output mode where supported
            response = self.client.chat(
                model=self.model,
                messages=messages,
                format="json",
            )
            raw = response.message.content
        except Exception:
            # Fallback: without format constraint
            response = self.client.chat(
                model=self.model,
                messages=messages,
            )
            raw = response.message.content

        analysis = _clean_json(raw)
        analysis["model"] = f"ollama/{self.model}"
        analysis["mode"]  = "air-gapped-local"
        return analysis


# ─────────────────────────────────────────────────────────
# Hybrid ThreatAdvisor
# ─────────────────────────────────────────────────────────

class ThreatAdvisor:
    """
    Hybrid LLM threat advisor — Gemini API + Claude API + Ollama local + rule-based fallback.

    Mode routing:

      auto       → Gemini (if available, free & fast) → Claude → Ollama → rule-based
      gemini     → Gemini API → fallbacks
      claude     → Claude API → fallbacks
      ollama     → Ollama local → fallbacks
      air-gapped → Ollama local → rule-based (never uses cloud APIs)

    The `model` and `mode` fields in the returned dict identify
    which backend actually responded.
    """

    def __init__(
        self,
        mode: str = "auto",
        gemini_model: str = "gemini-flash-latest",
        ollama_model: str = "llama3.1",
        ollama_host: str = "http://localhost:11434",
        claude_model: str = "claude-sonnet-4-6",
        max_tokens: int = 1500,
    ):
        self.mode = mode

        self._claude = ClaudeBackend(
            model=claude_model,
            max_tokens=max_tokens,
        )
        self._gemini = GeminiBackend(
            model=gemini_model,
        )
        # Don't initialise Ollama in pure cloud modes (claude/gemini)
        if mode not in ("claude", "gemini"):
            self._ollama = OllamaBackend(
                model=ollama_model,
                host=ollama_host,
            )
        else:
            self._ollama = None

        logger.info(
            f"ThreatAdvisor ready — mode: {mode} | "
            f"gemini: {'OK' if self._gemini.available else 'unavailable'} | "
            f"claude: {'OK' if self._claude.available else 'unavailable'} | "
            f"ollama: {'OK' if self._ollama and self._ollama.available else 'unavailable'}"
        )

    def should_invoke_llm(self, anomaly: dict) -> bool:
        """
        Air-Gapped Response Strategy (Security Guard vs Detective Tiering):
        - CRITICAL / HIGH severity: Always invoke LLM for full threat reasoning.
        - MEDIUM severity: Invoke LLM if anomaly_score >= 70 or is_write is True.
        - LOW severity / background noise: Use rule-based engine directly to preserve
          edge CPU/RAM resources and avoid LLM inference fatigue.
        """
        severity = anomaly.get("severity", "LOW")
        score = anomaly.get("anomaly_score", 0.0)
        is_write = anomaly.get("is_write", False)

        if severity in ("CRITICAL", "HIGH"):
            return True
        elif severity == "MEDIUM" and (score >= 70.0 or is_write):
            return True
        return False

    # ── Public API ────────────────────────────────────────────

    def analyze(self, anomaly: dict) -> dict:
        """
        Analyze an OT anomaly using the configured LLM backend.

        Returns a dict with threat_summary, possible_causes,
        immediate_actions, iec62443_reference, and more.
        See module docstring for full output schema.
        """
        severity = anomaly.get("severity", "LOW")

        # Response Tiering Check: Preserve LLM resources for high-value threats
        if not self.should_invoke_llm(anomaly):
            logger.info(
                f"[Tiering Filter] Event {anomaly.get('device_id')} ({severity}) "
                f"handled by ML baseline — LLM skipped to preserve edge CPU"
            )
            return self._fallback_analysis(anomaly)

        try:
            if self.mode == "gemini":
                return self._try_gemini(anomaly)

            elif self.mode in ("ollama", "air-gapped"):
                return self._try_ollama(anomaly)

            elif self.mode == "claude":
                return self._try_claude(anomaly)

            else:  # auto
                if self._gemini.available:
                    return self._try_gemini(anomaly)
                elif severity == "CRITICAL" and self._claude.available:
                    return self._try_claude(anomaly)
                elif self._ollama and self._ollama.available:
                    return self._try_ollama(anomaly)
                elif self._claude.available:
                    return self._try_claude(anomaly)
                else:
                    logger.warning(
                        "No LLM backend available — using rule-based fallback"
                    )
                    return self._fallback_analysis(anomaly)

        except Exception as exc:
            logger.error(f"All LLM backends failed: {exc}")
            return self._fallback_analysis(anomaly)

    # ── Backend wrappers with fallback ────────────────────────

    def _try_gemini(self, anomaly: dict) -> dict:
        try:
            analysis = self._gemini.analyze(anomaly)
            analysis = self._finalize(analysis, anomaly)
            logger.info(
                f"[Gemini/{self._gemini.model}] {anomaly.get('device_id')} | "
                f"score={anomaly.get('anomaly_score')} | "
                f"escalate={analysis.get('escalate_immediately')}"
            )
            return analysis
        except Exception as exc:
            logger.warning(f"Gemini failed ({exc}) — trying fallbacks")
            if self._claude and self._claude.available:
                return self._try_claude(anomaly)
            elif self._ollama and self._ollama.available:
                return self._try_ollama(anomaly)
            return self._fallback_analysis(anomaly)

    # ── Backend wrappers with fallback ────────────────────────

    def _try_claude(self, anomaly: dict) -> dict:
        try:
            analysis = self._claude.analyze(anomaly)
            analysis = self._finalize(analysis, anomaly)
            logger.info(
                f"[Claude] {anomaly.get('device_id')} | "
                f"score={anomaly.get('anomaly_score')} | "
                f"escalate={analysis.get('escalate_immediately')}"
            )
            return analysis
        except Exception as exc:
            logger.warning(f"Claude failed ({exc}) — trying Ollama")
            if self._ollama and self._ollama.available:
                return self._try_ollama(anomaly)
            return self._fallback_analysis(anomaly)

    def _try_ollama(self, anomaly: dict) -> dict:
        try:
            analysis = self._ollama.analyze(anomaly)
            analysis = self._finalize(analysis, anomaly)
            logger.info(
                f"[Ollama/{self._ollama.model}] {anomaly.get('device_id')} | "
                f"score={anomaly.get('anomaly_score')} | "
                f"escalate={analysis.get('escalate_immediately')}"
            )
            return analysis
        except Exception as exc:
            logger.warning(f"Ollama failed ({exc}) — using rule-based fallback")
            return self._fallback_analysis(anomaly)

    def _finalize(self, analysis: dict, anomaly: dict) -> dict:
        """Stamp common fields onto a successful LLM response."""
        analysis["analyzed_at"] = datetime.now().isoformat()
        analysis["success"]     = True
        # Inject deterministic MITRE Mapping
        analysis["mitre_attack_ics"] = self._map_mitre_ics(anomaly.get("function_code", 0), anomaly.get("is_write", False))
        # Ensure schema completeness — fill missing keys with None
        for key in ("analyst_notes", "operational_impact", "data_integrity_risk"):
            analysis.setdefault(key, None)
        return analysis

    def _map_mitre_ics(self, fc: int, is_write: bool) -> str:
        """Deterministic MITRE ATT&CK for ICS Mapping."""
        if fc == 43:
            return "T0846 — Remote System Discovery"
        elif fc in (15, 16):
            return "T0836 — Modify Parameter"
        elif fc in (5, 6):
            return "T0855 — Unauthorized Command Message"
        elif fc == 90:
            return "T0843 — Program Upload"
        elif is_write:
            return "T0836 — Modify Parameter"
        return "None (Routine Polling)"

    # ── Rule-based fallback (no LLM required) ─────────────────

    def _fallback_analysis(self, anomaly: dict) -> dict:
        """
        Deterministic rule-based analysis.
        Used when all LLM backends are unavailable.
        Covers the most common OT threat patterns.
        """
        severity = anomaly.get("severity", "MEDIUM")
        score    = anomaly.get("anomaly_score", 0)
        is_write = anomaly.get("is_write", False)
        fc       = anomaly.get("function_code", 0)
        device   = anomaly.get("device_id", "OT device")

        if fc == 43:
            summary = (
                f"Device identification scan (FC=43) detected targeting "
                f"{device} — classic reconnaissance signature"
            )
            actions = [
                "Block source IP at OT network perimeter immediately",
                "Check firewall logs for additional scan traffic",
                "Verify no legitimate maintenance activity is scheduled",
                "Enable enhanced logging on target device",
            ]
            iec_req = "SR 1.1 — Identification and Authentication"
            escalate = True

        elif is_write:
            summary = (
                f"Unauthorized write command (FC={fc}) detected on "
                f"{device} — immediate investigation required"
            )
            actions = [
                "Identify source of write command — verify authorization",
                "Check change management records for approved changes",
                "Inspect OT device for unexpected configuration changes",
                "Review network logs for source IP lateral movement",
            ]
            iec_req = "SR 2.1 — Authorization Enforcement"
            escalate = True

        elif score >= 70:
            summary = (
                f"High anomaly score ({score}/100) on {device} "
                f"— significant behavioral deviation from baseline"
            )
            actions = [
                "Investigate source IP for unauthorized access patterns",
                "Review network traffic logs around this timestamp",
                "Verify OT device is operating within normal parameters",
                "Check for any recent network topology changes",
            ]
            iec_req = "SR 6.2 — Continuous Monitoring"
            escalate = score >= 80

        else:
            summary = (
                f"Moderate anomaly ({score}/100) on {device} "
                f"— monitor and investigate"
            )
            actions = [
                "Monitor device for continued anomalous behavior",
                "Review operational logs for additional context",
                "Verify normal operational activity with site engineer",
            ]
            iec_req = "SR 6.2 — Continuous Monitoring"
            escalate = False

        return {
            "threat_summary": summary,
            "threat_detail": (
                f"Anomaly score {score}/100 detected on "
                f"{anomaly.get('protocol', 'OT protocol')} traffic. "
                f"Rule-based analysis applied (LLM backends unavailable)."
            ),
            "possible_causes": [
                {
                    "rank": 1,
                    "cause": "Unauthorized network access attempt",
                    "likelihood": "40%",
                    "type": "malicious",
                },
                {
                    "rank": 2,
                    "cause": "Misconfigured automation or SCADA system",
                    "likelihood": "35%",
                    "type": "operational",
                },
                {
                    "rank": 3,
                    "cause": "Network or hardware fault",
                    "likelihood": "25%",
                    "type": "technical",
                },
            ],
            "immediate_actions": actions,
            "iec62443_reference": {
                "requirement":  iec_req.split(" — ")[0],
                "title":        iec_req.split(" — ")[1] if " — " in iec_req else "",
                "description":  "Manual investigation required — LLM unavailable",
            },
            "operational_impact":   "high" if score >= 70 else "medium",
            "data_integrity_risk":  bool(is_write),
            "escalate_immediately": escalate,
            "escalation_reason": (
                "Score or command type requires immediate human review"
                if escalate else "Monitor and review at next opportunity"
            ),
            "mitre_attack_ics": self._map_mitre_ics(fc, is_write),
            "analyst_notes": (
                "Rule-based fallback — configure ANTHROPIC_API_KEY "
                "or start Ollama (ollama serve) for full LLM analysis"
            ),
            "analyzed_at": datetime.now().isoformat(),
            "model":       "rule-based-fallback",
            "mode":        "rule-based",
            "success":     True,
        }

    # ── Alert formatting ──────────────────────────────────────

    def format_alert_message(self, anomaly: dict, analysis: dict) -> str:
        """Format analysis for Telegram / Email notification channels."""
        severity  = anomaly.get("severity", "UNKNOWN")
        score     = anomaly.get("anomaly_score", 0)
        device    = anomaly.get("device_id", "Unknown")
        timestamp = anomaly.get("timestamp", "")
        backend   = analysis.get("model", "unknown")

        emoji = {
            "CRITICAL": "ALERT",
            "HIGH":     "WARNING",
            "MEDIUM":   "NOTICE",
            "LOW":      "INFO",
        }.get(severity, "?")

        lines = [
            f"[{emoji}] SECUREBRIDGE — {severity}",
            f"Device: {device}",
            f"Score : {score}/100",
            f"Time  : {timestamp}",
            f"Engine: {backend}",
            f"",
            f"WHAT HAPPENED:",
            analysis.get("threat_summary", "Analysis unavailable"),
            f"",
            f"IMMEDIATE ACTIONS:",
        ]

        for i, action in enumerate(
            analysis.get("immediate_actions", [])[:3], 1
        ):
            lines.append(f"{i}. {action}")

        iec = analysis.get("iec62443_reference", {})
        if iec:
            lines.extend([
                f"",
                f"IEC 62443: {iec.get('requirement')} -- {iec.get('title')}",
            ])

        if analysis.get("escalate_immediately"):
            lines.extend([
                f"",
                f"[ESCALATE TO HUMAN ANALYST IMMEDIATELY]",
                f"Reason: {analysis.get('escalation_reason', '')}",
            ])

        return "\n".join(lines)


# ─────────────────────────────────────────────────────────
# CLI Test
# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    test_anomaly = {
        "device_id":        "PLC-01",
        "protocol":         "Modbus TCP",
        "event_type":       "MODBUS_WRITE",
        "anomaly_score":    87.5,
        "severity":         "CRITICAL",
        "src_ip":           "192.168.10.199",
        "dst_ip":           "192.168.40.10",
        "function_code":    6,
        "function_name":    "Write Single Register",
        "register_address": 40001,
        "is_write":         True,
        "timestamp":        datetime.now().isoformat(),
        "flags": {
            "high_risk_function": "High-risk Modbus command: Write Single Register (risk=8/10)",
            "write_command":      "Write command to register 40001",
        },
    }

    mode = sys.argv[1] if len(sys.argv) > 1 else "auto"
    print(f"\nThreatAdvisor test — mode: {mode}")

    advisor  = ThreatAdvisor(mode=mode)
    analysis = advisor.analyze(test_anomaly)
    alert    = advisor.format_alert_message(test_anomaly, analysis)

    print("\n" + alert)
    print("\n--- Full Analysis ---")
    print(json.dumps(analysis, indent=2, default=str))
