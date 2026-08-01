"""
SecureBridge — Hybrid LLM Threat Advisor
Supports two deployment modes:

  CLOUD MODE:    Claude API (Anthropic) — best quality analysis
  AIR-GAPPED:    Ollama local LLM — zero data leaves the network

Auto mode: CRITICAL alerts → Claude, routine → Ollama
Sandy Lukita | PT Optima Sarana Instrument
"""

import os, sys, json, logging
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
logger = logging.getLogger("SecureBridge.Advisor")

SYSTEM_PROMPT = """You are an expert OT/ICS Cybersecurity Analyst with 20 years experience
in critical infrastructure. You specialize in Modbus TCP, DNP3, IEC 62443, Purdue Model.
In OT environments, Availability > Confidentiality. Never recommend actions causing downtime."""

ANALYSIS_PROMPT = """Analyze this OT/ICS anomaly. Respond ONLY in valid JSON:
Device: {device_id} | Protocol: {protocol} | Score: {anomaly_score}/100
Severity: {severity} | Event: {event_type} | Write: {is_write}
Source: {src_ip} → {dst_ip} | Function: {function_code} ({function_name})

{{
  "threat_summary": "one sentence plain English",
  "threat_detail": "2-3 sentence technical explanation",
  "possible_causes": [
    {{"rank": 1, "cause": "desc", "likelihood": "65%", "type": "malicious/operational/technical"}},
    {{"rank": 2, "cause": "desc", "likelihood": "25%", "type": "malicious/operational/technical"}},
    {{"rank": 3, "cause": "desc", "likelihood": "10%", "type": "malicious/operational/technical"}}
  ],
  "immediate_actions": ["action 1", "action 2", "action 3"],
  "iec62443_reference": {{"requirement": "SR X.X", "title": "title", "description": "relevance"}},
  "operational_impact": "low/medium/high/critical",
  "data_integrity_risk": true/false,
  "escalate_immediately": true/false,
  "escalation_reason": "reason",
  "mitre_attack_ics": "T0XXX — name or null",
  "analyst_notes": "additional context"
}}"""


class ThreatAdvisor:
    """
    Hybrid LLM: Claude API (cloud) + Ollama (air-gapped local)
    
    Auto mode routing:
    - CRITICAL → Claude (best quality)
    - HIGH/MEDIUM/LOW → Ollama (cost efficient, data stays local)
    - No LLM available → rule-based fallback
    """

    def __init__(self, mode="auto", ollama_model="llama3.1",
                 ollama_host="http://ollama:11434"):
        self.mode = mode
        self.ollama_model = ollama_model
        self.ollama_host = ollama_host
        self._claude = None
        self._ollama = None
        self._claude_ok = False
        self._ollama_ok = False
        self._init_claude()
        self._init_ollama()
        logger.info(f"Advisor ready | mode={mode} | claude={self._claude_ok} | ollama={self._ollama_ok}")

    def _init_claude(self):
        try:
            import anthropic
            key = os.getenv("ANTHROPIC_API_KEY")
            if key:
                self._claude = anthropic.Anthropic(api_key=key)
                self._claude_ok = True
                logger.info("Claude API connected")
        except Exception as e:
            logger.info(f"Claude unavailable: {e}")

    def _init_ollama(self):
        try:
            import ollama as _ollama
            client = _ollama.Client(host=self.ollama_host)
            client.list()
            self._ollama = client
            self._ollama_ok = True
            logger.info(f"Ollama connected: {self.ollama_host} model={self.ollama_model}")
        except Exception as e:
            logger.info(f"Ollama unavailable: {e}")

    def _route(self, severity):
        if self.mode == "air-gapped":
            return "ollama" if self._ollama_ok else "fallback"
        if self.mode == "cloud":
            return "claude" if self._claude_ok else "fallback"
        # auto
        if severity == "CRITICAL" and self._claude_ok:
            return "claude"
        if self._ollama_ok:
            return "ollama"
        if self._claude_ok:
            return "claude"
        return "fallback"

    def analyze(self, anomaly: dict) -> dict:
        severity = anomaly.get("severity", "MEDIUM")
        route = self._route(severity)
        logger.info(f"Routing {severity} alert → {route}")
        
        if route == "claude":
            result = self._claude_analyze(anomaly)
        elif route == "ollama":
            result = self._ollama_analyze(anomaly)
        else:
            result = self._fallback(anomaly)
        
        result["llm_mode"] = route
        result["analyzed_at"] = datetime.now().isoformat()
        return result

    def _build_prompt(self, anomaly):
        return ANALYSIS_PROMPT.format(
            device_id=anomaly.get("device_id","Unknown"),
            protocol=anomaly.get("protocol","Modbus TCP"),
            event_type=anomaly.get("event_type","Unknown"),
            anomaly_score=anomaly.get("anomaly_score",0),
            severity=anomaly.get("severity","UNKNOWN"),
            src_ip=anomaly.get("src_ip","Unknown"),
            dst_ip=anomaly.get("dst_ip","Unknown"),
            function_code=anomaly.get("function_code",""),
            function_name=anomaly.get("function_name",""),
            is_write=anomaly.get("is_write",False)
        )

    def _clean_json(self, raw):
        raw = raw.strip()
        if "```" in raw:
            for part in raw.split("```"):
                p = part.strip().lstrip("json").strip()
                if p.startswith("{"):
                    return p
        return raw

    def _claude_analyze(self, anomaly):
        try:
            r = self._claude.messages.create(
                model="claude-sonnet-4-6", max_tokens=1500,
                system=SYSTEM_PROMPT,
                messages=[{"role":"user","content":self._build_prompt(anomaly)}]
            )
            result = json.loads(self._clean_json(r.content[0].text))
            result["model"] = "claude-sonnet-4-6"
            result["success"] = True
            result["air_gapped"] = False
            return result
        except Exception as e:
            logger.error(f"Claude failed: {e}")
            return self._ollama_analyze(anomaly) if self._ollama_ok else self._fallback(anomaly)

    def _ollama_analyze(self, anomaly):
        """Air-gapped local LLM — zero data leaves the network"""
        try:
            prompt = f"{SYSTEM_PROMPT}\n\n{self._build_prompt(anomaly)}"
            r = self._ollama.chat(
                model=self.ollama_model,
                messages=[{"role":"user","content":prompt}],
                format="json",
                options={"temperature":0.1,"num_predict":1024}
            )
            result = json.loads(self._clean_json(r["message"]["content"]))
            result["model"] = f"ollama/{self.ollama_model}"
            result["success"] = True
            result["air_gapped"] = True
            return result
        except Exception as e:
            logger.error(f"Ollama failed: {e}")
            return self._fallback(anomaly)

    def _fallback(self, anomaly):
        score = anomaly.get("anomaly_score",0)
        is_write = anomaly.get("is_write",False)
        device = anomaly.get("device_id","Unknown")
        return {
            "threat_summary": f"{'Write command' if is_write else 'Anomaly'} detected on {device}",
            "threat_detail": f"Score {score}/100. Rule-based analysis (no LLM available).",
            "possible_causes": [
                {"rank":1,"cause":"Unauthorized access","likelihood":"40%","type":"malicious"},
                {"rank":2,"cause":"Misconfigured system","likelihood":"35%","type":"operational"},
                {"rank":3,"cause":"Hardware fault","likelihood":"25%","type":"technical"}
            ],
            "immediate_actions": [
                "Investigate source IP",
                "Review network traffic logs",
                "Verify OT device status"
            ],
            "iec62443_reference": {"requirement":"SR 6.2","title":"Continuous Monitoring","description":"Baseline deviation"},
            "operational_impact": "high" if score >= 70 else "medium",
            "data_integrity_risk": is_write,
            "escalate_immediately": is_write or score >= 80,
            "escalation_reason": "High risk indicator detected",
            "mitre_attack_ics": "T0855 — Unauthorized Command Message" if is_write else None,
            "analyst_notes": "Set ANTHROPIC_API_KEY or start Ollama for full AI analysis",
            "model": "rule-based-fallback",
            "success": True,
            "air_gapped": False
        }

    def format_alert(self, anomaly, analysis):
        sev = anomaly.get("severity","UNKNOWN")
        emoji = {"CRITICAL":"🚨","HIGH":"⚠️","MEDIUM":"🔔","LOW":"ℹ️"}.get(sev,"❓")
        air = "🔒 Air-gapped — data stayed local\n" if analysis.get("air_gapped") else ""
        lines = [
            f"{emoji} SECUREBRIDGE — {sev}",
            f"Device: {anomaly.get('device_id')} | Score: {anomaly.get('anomaly_score')}/100",
            f"Model: {analysis.get('model','unknown')} | {air}",
            f"📋 {analysis.get('threat_summary','')}",
            "⚡ Actions:"
        ]
        for i,a in enumerate(analysis.get("immediate_actions",[])[:3],1):
            lines.append(f"  {i}. {a}")
        iec = analysis.get("iec62443_reference",{})
        if iec:
            lines.append(f"📖 {iec.get('requirement')} — {iec.get('title')}")
        if analysis.get("escalate_immediately"):
            lines.append(f"🔺 ESCALATE: {analysis.get('escalation_reason')}")
        return "\n".join(lines)

    @property
    def status(self):
        return {
            "mode": self.mode,
            "claude_available": self._claude_ok,
            "ollama_available": self._ollama_ok,
            "ollama_model": self.ollama_model,
            "ollama_host": self.ollama_host
        }

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    mode = sys.argv[1] if len(sys.argv) > 1 else "auto"
    advisor = ThreatAdvisor(mode=mode)
    print(json.dumps(advisor.status, indent=2))
    test = {
        "device_id":"PLC-01","protocol":"Modbus TCP",
        "event_type":"MODBUS_WRITE","anomaly_score":92.5,
        "severity":"CRITICAL","src_ip":"192.168.10.199",
        "dst_ip":"192.168.40.10","function_code":6,
        "function_name":"Write Single Register",
        "is_write":True,"timestamp":datetime.now().isoformat()
    }
    result = advisor.analyze(test)
    print("\n" + advisor.format_alert(test, result))
