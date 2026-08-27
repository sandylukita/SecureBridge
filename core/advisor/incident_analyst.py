"""
SecureBridge — Hybrid LLM Threat Advisor
=========================================
Provides intelligent OT/ICS threat analysis with multiple backends:

  Groq API     (cloud)    — default, lightning fast, Llama 3 models
  Claude API   (cloud)    — highest quality reasoning, CRITICAL alerts
  Gemini API   (cloud)    — free tier, fast
  Ollama local (on-prem)  — air-gapped environments, zero data egress

Backend selection is controlled by config.llm.provider:

  groq       — Always Groq API (requires GROQ_API_KEY)
  auto       — Groq/Gemini/Claude if available, fallback to Ollama/Rule engine
  claude     — Always Claude API (requires ANTHROPIC_API_KEY)
  ollama     — Always local Ollama (air-gapped / offline)
  air-gapped — Alias for ollama; makes intent explicit in YAML config

Both backends use the identical prompt schema and return the same JSON
structure — the dashboard and alerting layer never need to know which
backend was used. A model/provider field in the response identifies the source.

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
  provider             : cloud / air-gapped-local / rule-based
  success              : bool
  latency_sec          : float (time taken for inference)
  request_id           : string (debugging context)
"""

import os
import sys
import json
import logging
import anthropic
import time
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


INCIDENT_ANALYSIS_PROMPT = """Analyze this OT/ICS security incident and provide
a structured assessment. An incident consists of a sequence of related alerts
grouped by the source and destination asset.

INCIDENT SUMMARY:
- Incident ID: {incident_id}
- Target Asset (Destination): {dst_ip}
- Source Asset: {src_ip}
- Source Classification (Role): {role_label}
{role_context_note}
- Total Alerts in Window: {alert_count}
- Highest Severity: {severity} (Score: {max_score}/100)
- Protocol(s): {protocols}

EVENT SEQUENCE (Compressed):
{compressed_sequence}

Respond ONLY with valid JSON in this exact format:
{{
  "threat_summary": "One sentence — what happened in plain English across this incident",
  "threat_detail": "2-3 sentences — technical explanation of the sequence for security team",
  "possible_causes": [
    {{"rank": 1, "cause": "description", "likelihood": "65%", "type": "malicious/operational/technical"}},
    {{"rank": 2, "cause": "description", "likelihood": "25%", "type": "malicious/operational/technical"}}
  ],
  "immediate_actions": [
    "Action 1 — specific and actionable",
    "Action 2 — specific and actionable"
  ],
  "iec62443_reference": {{
    "sr_id": "SR X.X",
    "title": "Requirement title",
    "description": "How this incident relates to this requirement"
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


def _build_incident_summary(incident: dict) -> str:
    """Compress a sequence of alerts into a text summary to save LLM tokens."""
    alerts = incident.get("alerts", [])
    if not alerts:
        return "No alerts found."

    summary_lines = []
    current_batch = None
    count = 0

    for alt in alerts:
        fc = alt.get("function_code", "N/A")
        fc_name = alt.get("function_name", "Unknown")
        is_write = alt.get("is_write", False)
        
        signature = f"FC{fc} ({fc_name}) | Write: {is_write}"
        
        if current_batch == signature:
            count += 1
        else:
            if current_batch is not None:
                summary_lines.append(f"- Repeated {count}x: {current_batch}")
            current_batch = signature
            count = 1

    if current_batch is not None:
        summary_lines.append(f"- Repeated {count}x: {current_batch}")

    return "\n".join(summary_lines)

def _build_role_context_note(role_label: str, is_write: bool) -> str:
    """Build context notes for the LLM based on source classification."""
    if role_label == "Source (SCADA)" and not is_write:
        return (
            "NOTE: This traffic originates from a KNOWN, LEGITIMATE "
            "SCADA workstation performing READ-ONLY polling. This is "
            "NOT an attack. Your analysis should reflect this — do NOT "
            "recommend isolating or blocking this source. Frame this as "
            "routine operational traffic, and if volume is unusually "
            "high, recommend investigating WHY polling frequency "
            "increased, not blocking the source."
        )
    elif role_label == "Suspicious Source":
        return (
            "NOTE: This source IP is unrecognized and exhibits abnormal "
            "behavior (e.g., unusual frequency) but has NOT executed any "
            "write commands. Treat as reconnaissance/scanning risk, "
            "not confirmed compromise."
        )
    elif role_label == "Attacker" or role_label == "Compromised SCADA":
        return (
            "NOTE: This source has been confirmed to execute unauthorized "
            "write commands. Treat as active threat requiring immediate "
            "containment."
        )
    return ""


def _build_incident_prompt(incident: dict) -> str:
    """Render INCIDENT_ANALYSIS_PROMPT with compressed incident data."""
    alerts = incident.get("alerts", [])
    protocols = list(set(alt.get("protocol", "Modbus TCP") for alt in alerts))
    
    # Extract role info to build prompt context
    role_label = incident.get("role_label", "Unknown Source")
    is_write = any(alt.get("is_write", False) for alt in alerts)
    role_context_note = _build_role_context_note(role_label, is_write)
    
    return INCIDENT_ANALYSIS_PROMPT.format(
        incident_id=incident.get("incident_id", "Unknown"),
        dst_ip=incident.get("target_ip", "Unknown"),
        src_ip=incident.get("source_ip", "Unknown"),
        role_label=role_label,
        role_context_note=role_context_note,
        alert_count=incident.get("alert_count", 0),
        severity=incident.get("severity", "UNKNOWN"),
        max_score=incident.get("max_score", 0.0),
        protocols=", ".join(protocols),
        compressed_sequence=_build_incident_summary(incident)
    )

# ─────────────────────────────────────────────────────────
# Groq Backend
# ─────────────────────────────────────────────────────────

class GroqBackend:
    """
    Groq API backend.
    Requires GROQ_API_KEY environment variable.
    Provides sub-second inference using Llama 3 models on LPUs.
    """

    def __init__(self, model: str = "llama-3.3-70b-versatile", max_tokens: int = 1500, timeout: int = 8):
        self.model      = model
        self.max_tokens = max_tokens
        self.timeout    = timeout
        self.client     = None
        self.available  = False
        self._init()

    def _init(self):
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            logger.warning(
                "GROQ_API_KEY not set — Groq backend unavailable. "
            )
            return
        try:
            from groq import Groq
            self.client    = Groq(api_key=api_key, timeout=self.timeout, max_retries=0)
            self.available = True
            logger.info(f"Groq backend ready — model: {self.model}")
        except Exception as exc:
            logger.warning(f"Groq init failed: {exc}")

    def analyze_incident(self, incident: dict) -> dict:
        if not self.client:
            raise RuntimeError("Groq client not initialized")

        prompt   = _build_incident_prompt(incident)
        
        t0 = time.perf_counter()
        response = self.client.chat.completions.create(
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=0.0,
            response_format={"type": "json_object"},
        )
        t1 = time.perf_counter()
        
        raw      = response.choices[0].message.content
        analysis = _clean_json(raw)
        analysis["model"] = f"groq/{self.model}"
        analysis["provider"] = "groq"
        analysis["latency_sec"] = round(t1 - t0, 2)
        analysis["request_id"] = getattr(response, 'id', 'unknown')
        return analysis

# ─────────────────────────────────────────────────────────
# Claude Backend
# ─────────────────────────────────────────────────────────

class ClaudeBackend:
    """
    Anthropic Claude API backend.
    Requires ANTHROPIC_API_KEY environment variable.
    Provides highest-quality threat reasoning for complex incidents.
    """

    def __init__(self, model: str = "claude-sonnet-4-6", max_tokens: int = 1500, timeout: int = 8):
        self.model      = model
        self.max_tokens = max_tokens
        self.timeout    = timeout
        self.client     = None
        self.available  = False
        self._init()

    def _init(self):
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            logger.warning(
                "ANTHROPIC_API_KEY not set — Claude backend unavailable. "
            )
            return
        try:
            self.client    = anthropic.Anthropic(api_key=api_key, max_retries=0, timeout=self.timeout)
            self.available = True
            logger.info(f"Claude backend ready — model: {self.model}")
        except Exception as exc:
            logger.warning(f"Claude init failed: {exc}")

    def analyze_incident(self, incident: dict) -> dict:
        if not self.client:
            raise RuntimeError("Claude client not initialized")

        prompt   = _build_incident_prompt(incident)
        
        t0 = time.perf_counter()
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        t1 = time.perf_counter()
        
        raw      = response.content[0].text
        analysis = _clean_json(raw)
        analysis["model"] = f"claude/{self.model}"
        analysis["provider"]  = "claude"
        analysis["latency_sec"] = round(t1 - t0, 2)
        analysis["request_id"] = getattr(response, 'id', 'unknown')
        return analysis


# ─────────────────────────────────────────────────────────
# Gemini Backend
# ─────────────────────────────────────────────────────────

class GeminiBackend:
    """
    Google Gemini API backend.
    Requires GEMINI_API_KEY environment variable.
    """

    def __init__(self, model: str = "gemini-flash-latest", timeout: int = 8):
        self.model     = model
        self.timeout   = timeout
        self.client    = None
        self.available = False
        self._init()

    def _init(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            logger.warning(
                "GEMINI_API_KEY not set — Gemini backend unavailable. "
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

    def analyze_incident(self, incident: dict) -> dict:
        if not self.client:
            raise RuntimeError("Gemini client not initialized")

        prompt = _build_incident_prompt(incident)
        generation_config = {"response_mime_type": "application/json"}
        
        from google.api_core import retry
        
        t0 = time.perf_counter()
        response = self.client.generate_content(
            prompt,
            generation_config=generation_config,
            request_options={"retry": retry.Retry(initial=0, maximum=0, timeout=float(self.timeout))}
        )
        t1 = time.perf_counter()
        
        raw = response.text
        analysis = _clean_json(raw)
        analysis["model"] = f"gemini/{self.model}"
        analysis["provider"]  = "gemini"
        analysis["latency_sec"] = round(t1 - t0, 2)
        analysis["request_id"] = 'gemini-req'
        return analysis


# ─────────────────────────────────────────────────────────
# Ollama Backend
# ─────────────────────────────────────────────────────────

class OllamaBackend:
    """
    Local Ollama backend — air-gapped / offline mode.
    """

    def __init__(
        self,
        model: str = "llama3.1",
        host: str = "http://localhost:11434",
        timeout: int = 15,
    ):
        self.model     = model
        self.host      = host
        self.timeout   = timeout
        self.client    = None
        self.available = False
        self._init()

    def _init(self):
        try:
            import ollama as _ollama
            # Override host if non-default
            if self.host != "http://localhost:11434":
                self.client = _ollama.Client(host=self.host, timeout=self.timeout)
            else:
                self.client = _ollama.Client(host=self.host, timeout=self.timeout)
                
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

    def analyze_incident(self, incident: dict) -> dict:
        if not self.client:
            raise RuntimeError("Ollama client not initialized")

        # Combine system + user prompt (Ollama supports system role)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": _build_incident_prompt(incident)},
        ]

        t0 = time.perf_counter()
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
        t1 = time.perf_counter()

        analysis = _clean_json(raw)
        analysis["model"] = f"ollama/{self.model}"
        analysis["provider"]  = "ollama"
        analysis["latency_sec"] = round(t1 - t0, 2)
        analysis["request_id"] = "local-inference"
        return analysis


# ─────────────────────────────────────────────────────────
# Hybrid ThreatAdvisor
# ─────────────────────────────────────────────────────────

class IncidentAnalyst:
    """
    Hybrid LLM threat advisor — Groq API + Gemini API + Claude API + Ollama local + rule-based fallback.

    Provider routing:

      groq       → Groq API → fallbacks
      auto       → Groq (if available, free & fast) → Gemini → Claude → Ollama → rule-based
      gemini     → Gemini API → fallbacks
      claude     → Claude API → fallbacks
      ollama     → Ollama local → fallbacks
      air-gapped → Ollama local → rule-based (never uses cloud APIs)

    The `model` and `provider` fields in the returned dict identify
    which backend actually responded.
    """

    def __init__(
        self,
        provider: str = "groq",
        groq_model: str = "llama-3.3-70b-versatile",
        gemini_model: str = "gemini-flash-latest",
        ollama_model: str = "llama3.1",
        ollama_host: str = "http://localhost:11434",
        claude_model: str = "claude-sonnet-4-6",
        max_tokens: int = 1500,
        api_timeout: int = 30,
    ):
        self.provider = provider
        
        self._groq = GroqBackend(
            model=groq_model,
            max_tokens=max_tokens,
            timeout=api_timeout
        )

        self._claude = ClaudeBackend(
            model=claude_model,
            max_tokens=max_tokens,
            timeout=api_timeout
        )
        self._gemini = GeminiBackend(
            model=gemini_model,
            timeout=api_timeout
        )
        
        # Don't initialise Ollama in pure cloud modes (unless auto)
        if provider not in ("claude", "gemini", "groq"):
            self._ollama = OllamaBackend(
                model=ollama_model,
                host=ollama_host,
                timeout=api_timeout*2 # Give local model more time
            )
        else:
            self._ollama = None

        logger.info(
            f"IncidentAnalyst ready — provider: {provider} | "
            f"groq: {'OK' if self._groq.available else 'unavailable'} | "
            f"gemini: {'OK' if self._gemini.available else 'unavailable'} | "
            f"claude: {'OK' if self._claude.available else 'unavailable'} | "
            f"ollama: {'OK' if self._ollama and self._ollama.available else 'unavailable'}"
        )

    def should_invoke_llm(self, incident: dict) -> bool:
        """
        Air-Gapped Response Strategy (Security Guard vs Detective Tiering):
        - CRITICAL / HIGH severity: Always invoke LLM for full threat reasoning.
        - MEDIUM severity: Invoke LLM if max score >= 70 or has write.
        - LOW severity / background noise: Use rule-based engine directly.
        """
        severity = incident.get("severity", "LOW")
        score = incident.get("max_score", 0.0)
        
        # Check if any alert in incident is a write
        is_write = any(a.get("is_write", False) for a in incident.get("alerts", []))

        if severity in ("CRITICAL", "HIGH"):
            return True
        elif severity == "MEDIUM" and (score >= 70.0 or is_write):
            return True
        return False

    # ── Public API ────────────────────────────────────────────

    def analyze_incident(self, incident: dict) -> dict:
        """
        Analyze an OT incident using the configured LLM backend.

        Returns a dict with threat_summary, possible_causes,
        immediate_actions, iec62443_reference, and more.
        See module docstring for full output schema.
        """
        severity = incident.get("severity", "LOW")

        # Response Tiering Check: Preserve LLM resources for high-value threats
        if not self.should_invoke_llm(incident):
            logger.info(
                f"[Tiering Filter] Incident {incident.get('incident_id')} ({severity}) "
                f"handled by ML baseline — LLM skipped to preserve edge CPU"
            )
            return self._fallback_analysis(incident)

        try:
            if self.provider == "groq":
                return self._try_groq(incident)

            elif self.provider == "gemini":
                return self._try_gemini(incident)

            elif self.provider in ("ollama", "air-gapped"):
                return self._try_ollama(incident)

            elif self.provider == "claude":
                return self._try_claude(incident)

            else:  # auto
                if self._groq.available:
                    return self._try_groq(incident)
                elif self._gemini.available:
                    return self._try_gemini(incident)
                elif severity == "CRITICAL" and self._claude.available:
                    return self._try_claude(incident)
                elif self._ollama and self._ollama.available:
                    return self._try_ollama(incident)
                elif self._claude.available:
                    return self._try_claude(incident)
                else:
                    logger.warning(
                        "No LLM backend available — using deterministic fallback"
                    )
                    return self._fallback_analysis(incident)

        except Exception as exc:
            logger.error(f"All LLM backends failed: {exc}")
            return self._fallback_analysis(incident)

    # ── Backend wrappers with fallback ────────────────────────

    def _try_groq(self, incident: dict) -> dict:
        try:
            analysis = self._groq.analyze_incident(incident)
            analysis = self._finalize(analysis, incident)
            logger.info(
                f"[Groq/{self._groq.model}] {incident.get('incident_id')} | "
                f"score={incident.get('max_score')} | "
                f"escalate={analysis.get('escalate_immediately')}"
            )
            return analysis
        except Exception as exc:
            logger.warning(f"Groq failed ({exc}) — trying fallbacks")
            if self._gemini and self._gemini.available:
                return self._try_gemini(incident)
            elif self._claude and self._claude.available:
                return self._try_claude(incident)
            elif self._ollama and self._ollama.available:
                return self._try_ollama(incident)
            return self._fallback_analysis(incident)

    def _try_gemini(self, incident: dict) -> dict:
        try:
            analysis = self._gemini.analyze_incident(incident)
            analysis = self._finalize(analysis, incident)
            logger.info(
                f"[Gemini/{self._gemini.model}] {incident.get('incident_id')} | "
                f"score={incident.get('max_score')} | "
                f"escalate={analysis.get('escalate_immediately')}"
            )
            return analysis
        except Exception as exc:
            logger.warning(f"Gemini failed ({exc}) — trying fallbacks")
            if self._claude and self._claude.available:
                return self._try_claude(incident)
            elif self._ollama and self._ollama.available:
                return self._try_ollama(incident)
            return self._fallback_analysis(incident)


    def _try_claude(self, incident: dict) -> dict:
        try:
            analysis = self._claude.analyze_incident(incident)
            analysis = self._finalize(analysis, incident)
            logger.info(
                f"[Claude] {incident.get('incident_id')} | "
                f"score={incident.get('max_score')} | "
                f"escalate={analysis.get('escalate_immediately')}"
            )
            return analysis
        except Exception as exc:
            logger.warning(f"Claude failed ({exc}) — trying Ollama")
            if self._ollama and self._ollama.available:
                return self._try_ollama(incident)
            return self._fallback_analysis(incident)

    def _try_ollama(self, incident: dict) -> dict:
        try:
            analysis = self._ollama.analyze_incident(incident)
            analysis = self._finalize(analysis, incident)
            logger.info(
                f"[Ollama/{self._ollama.model}] {incident.get('incident_id')} | "
                f"score={incident.get('max_score')} | "
                f"escalate={analysis.get('escalate_immediately')}"
            )
            return analysis
        except Exception as exc:
            logger.warning(f"Ollama failed ({exc}) — using rule-based fallback")
            return self._fallback_analysis(incident)

    def _finalize(self, analysis: dict, incident: dict) -> dict:
        """Stamp common fields onto a successful LLM response."""
        analysis["analyzed_at"] = datetime.now().isoformat()
        analysis["success"]     = True
        
        # Inject deterministic MITRE Mapping using representative alert
        alerts = incident.get("alerts", [])
        if alerts:
            # Sort by anomaly_score to find the representative one
            rep = sorted(alerts, key=lambda x: x.get("anomaly_score", 0), reverse=True)[0]
            analysis["mitre_attack_ics"] = self._map_mitre_ics(rep.get("function_code", 0), rep.get("is_write", False))
        else:
            analysis["mitre_attack_ics"] = "None"
            
        # Ensure schema completeness — fill missing keys with None
        for key in ("analyst_notes", "operational_impact", "data_integrity_risk", "latency_sec", "request_id"):
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

    def _fallback_analysis(self, incident: dict) -> dict:
        """
        Deterministic rule-based analysis for an incident.
        Used when all LLM backends are unavailable or timed out.
        """
        severity = incident.get("severity", "MEDIUM")
        score    = incident.get("max_score", 0)
        
        # Check if any alert is a write
        alerts = incident.get("alerts", [])
        is_write = any(a.get("is_write", False) for a in alerts)
        
        # Find if there are discovery scans
        has_discovery = any(a.get("function_code") == 43 for a in alerts)
        
        device   = incident.get("target_device_id", "OT device")

        if has_discovery:
            actions = [
                "Block source IP at OT network perimeter immediately",
                "Check firewall logs for additional scan traffic",
                "Verify no legitimate maintenance activity is scheduled",
                "Enable enhanced logging on target device",
            ]
            iec_req = "SR 1.1 — Identification and Authentication"
            escalate = True

        elif is_write:
            actions = [
                "Identify source of write command — verify authorization",
                "Check change management records for approved changes",
                "Inspect OT device for unexpected configuration changes",
                "Review network logs for source IP lateral movement",
            ]
            iec_req = "SR 2.1 — Authorization Enforcement"
            escalate = True

        elif score >= 70:
            actions = [
                "Investigate source IP for unauthorized access patterns",
                "Review network traffic logs around this timestamp",
                "Verify OT device is operating within normal parameters",
                "Check for any recent network topology changes",
            ]
            iec_req = "SR 6.2 — Continuous Monitoring"
            escalate = score >= 80

        else:
            actions = [
                "Monitor device for continued anomalous behavior",
                "Review operational logs for additional context",
                "Verify normal operational activity with site engineer",
            ]
            iec_req = "SR 6.2 — Continuous Monitoring"
            escalate = False

        return {
            "threat_summary": "No AI analysis available. AI service is currently offline or unreachable.",
            "threat_detail": (
                f"Incident max anomaly score {score}/100 detected. "
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
            "mitre_attack_ics": "T0836 — Modify Parameter" if is_write else ("T0846 — Remote System Discovery" if has_discovery else "None"),
            "analyst_notes": (
                "Rule-based fallback — configure GROQ_API_KEY "
                "or start Ollama (ollama serve) for full LLM analysis"
            ),
            "analyzed_at": datetime.now().isoformat(),
            "model":       "rule-based-fallback",
            "provider":    "rule-based",
            "success":     False,   # EXPLICITLY FALSE so dashboard can render fallback UI
            "latency_sec": 0.0,
            "request_id": "fallback"
        }

    # ── Alert formatting ──────────────────────────────────────

    def format_alert_message(self, incident: dict, analysis: dict) -> str:
        """Format analysis for Telegram / Email notification channels."""
        severity  = incident.get("severity", "UNKNOWN")
        score     = incident.get("max_score", 0)
        device    = incident.get("target_device_id", "Unknown")
        backend   = analysis.get("model", "unknown")

        emoji = {
            "CRITICAL": "ALERT",
            "HIGH":     "WARNING",
            "MEDIUM":   "NOTICE",
            "LOW":      "INFO",
        }.get(severity, "?")

        lines = [
            f"[{emoji}] SECUREBRIDGE — INCIDENT {severity}",
            f"Target: {device}",
            f"Max Score : {score}/100",
            f"Alerts: {incident.get('alert_count', 0)}",
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

    provider = sys.argv[1] if len(sys.argv) > 1 else "auto"
    print(f"\nIncidentAnalyst test — provider: {provider}")

    advisor  = IncidentAnalyst(provider=provider)
    
    test_incident = {
        "incident_id": "INC-TEST-001",
        "target_ip": "192.168.40.10",
        "target_device_id": "PLC-01",
        "source_ip": "192.168.10.199",
        "alert_count": 1,
        "severity": "CRITICAL",
        "max_score": 87.5,
        "alerts": [test_anomaly]
    }
    
    analysis = advisor.analyze_incident(test_incident)
    print("\n--- JSON OUTPUT ---")
    print(json.dumps(analysis, indent=2))
    print("\n--- TELEGRAM ALERT FORMAT ---")
    print(advisor.format_alert_message(test_incident, analysis))
