# SecureBridge — Firewall Rules Documentation
# IEC 62443 Zone and Conduit Model
# Author: Sandy Lukita | PT Optima Sarana Instrument

# ═══════════════════════════════════════════════════════════════
# ARCHITECTURE PRINCIPLE
# ═══════════════════════════════════════════════════════════════
#
# SecureBridge operates on PASSIVE monitoring principle:
# - It RECEIVES traffic via SPAN/TAP (no active connection to OT)
# - It SENDS alerts and reports UPWARD to IT zone only
# - It NEVER sends commands DOWNWARD to OT devices
# - Default policy: DENY ALL, then whitelist minimum required
#
# Traffic direction notation:
# → = allowed
# ✗ = explicitly denied
# ═ = data diode (hardware enforced, one direction only)

# ═══════════════════════════════════════════════════════════════
# FW-01: EDGE FIREWALL
# Internet → Corporate IT (Level 4)
# ═══════════════════════════════════════════════════════════════

FW-01 RULES:
┌─────────────────────────────────────────────────────────────────┐
│ Rule │ Source          │ Dest            │ Port    │ Action      │
├─────────────────────────────────────────────────────────────────┤
│  1   │ ANY             │ ANY (OT)        │ ANY     │ DENY ✗      │ ← OT never reachable from internet
│  2   │ Trusted VPN IPs │ Jump Server DMZ │ TCP 443 │ ALLOW →     │ ← Remote access via HTTPS only
│  3   │ ANY             │ Corporate WS    │ TCP 443 │ ALLOW →     │ ← HTTPS web browsing
│  4   │ ANY             │ Email Server    │ TCP 587 │ ALLOW →     │ ← Outbound email (alerts)
│  5   │ ANY             │ ANY             │ ANY     │ DENY ✗      │ ← Default deny
└─────────────────────────────────────────────────────────────────┘

# ═══════════════════════════════════════════════════════════════
# FW-02: OT FIREWALL
# Corporate IT (Level 4) ↔ DMZ
# ═══════════════════════════════════════════════════════════════
#
# KEY PRINCIPLE: IT cannot initiate connections to OT
# Only DMZ can receive data FROM OT (via data diode)
# SecureBridge in DMZ: receives SPAN traffic, sends alerts UP only

FW-02 RULES:
┌─────────────────────────────────────────────────────────────────────────────┐
│ Rule │ Source            │ Dest              │ Port      │ Action            │
├─────────────────────────────────────────────────────────────────────────────┤
│  1   │ Corporate IT      │ OT ANY            │ ANY       │ DENY ✗            │ ← IT CANNOT reach OT directly
│  2   │ Corporate IT      │ Historian DMZ     │ TCP 443   │ ALLOW → (read)    │ ← SOC reads historian via HTTPS
│  3   │ Corporate IT      │ Jump Server DMZ   │ TCP 443   │ ALLOW →           │ ← Admin access to jump server
│  4   │ Corporate IT      │ SecureBridge DMZ  │ TCP 8501  │ ALLOW →           │ ← Streamlit dashboard access
│  5   │ SecureBridge DMZ  │ Corporate SIEM    │ TCP 514   │ ALLOW → (syslog)  │ ← SecureBridge → SIEM (alerts)
│  6   │ SecureBridge DMZ  │ Email Server IT   │ TCP 587   │ ALLOW →           │ ← Alert emails
│  7   │ SecureBridge DMZ  │ Telegram API      │ TCP 443   │ ALLOW →           │ ← Telegram bot alerts
│  8   │ SecureBridge DMZ  │ OT ANY            │ ANY       │ DENY ✗            │ ← SecureBridge CANNOT send to OT
│  9   │ Historian DMZ     │ OT SCADA          │ TCP 4840  │ ALLOW → (OPC-UA)  │ ← Historian reads SCADA data
│ 10   │ Jump Server DMZ   │ Eng. WS SCADA     │ TCP 3389  │ ALLOW → (RDP)     │ ← Vendor access via jump only
│ 11   │ ANY               │ ANY               │ ANY       │ DENY ✗            │ ← Default deny
└─────────────────────────────────────────────────────────────────────────────┘

# ═══════════════════════════════════════════════════════════════
# DATA DIODE: OT → DMZ (HARDWARE ENFORCED)
# ═══════════════════════════════════════════════════════════════
#
# A data diode is a HARDWARE device (not software) that physically
# allows data to flow in ONE direction only.
# Even if SecureBridge is compromised, it CANNOT send commands to OT.
# This is the gold standard for OT security isolation.

DATA DIODE:
┌─────────────────────────────────────────────────────────────────┐
│ Source          │ Dest              │ Data           │ Direction │
├─────────────────────────────────────────────────────────────────┤
│ OT SCADA Zone   │ Historian DMZ     │ Process data   │ ══►       │
│ OT SCADA Zone   │ SecureBridge DMZ  │ SPAN traffic   │ ══►       │
│ Historian DMZ   │ OT SCADA Zone     │ ANYTHING       │ ✗ BLOCKED │
│ SecureBridge DMZ│ OT SCADA Zone     │ ANYTHING       │ ✗ BLOCKED │
└─────────────────────────────────────────────────────────────────┘
Hardware options: Waterfall Security, Owl Cyber Defense, Fox-IT

# ═══════════════════════════════════════════════════════════════
# FW-03: ICS FIREWALL
# DMZ ↔ Level 2 SCADA Zone
# ═══════════════════════════════════════════════════════════════
#
# Deepest firewall — OT protocol aware
# Must understand Modbus, DNP3, OPC-UA at application layer
# Recommended: Tofino Xenon, Fortinet FortiGate Rugged, Cisco ASA

FW-03 RULES:
┌──────────────────────────────────────────────────────────────────────────────┐
│ Rule │ Source          │ Dest            │ Port           │ Action            │
├──────────────────────────────────────────────────────────────────────────────┤
│  1   │ SCADA Server    │ PLC-01          │ TCP 502        │ ALLOW → (Modbus)  │ ← SCADA polls PLC via Modbus
│  2   │ SCADA Server    │ RTU-01          │ TCP 20000      │ ALLOW → (DNP3)    │ ← SCADA polls RTU via DNP3
│  3   │ SCADA Server    │ DCS             │ TCP 4840       │ ALLOW → (OPC-UA)  │ ← SCADA reads DCS via OPC-UA
│  4   │ Eng. WS         │ PLC-01          │ TCP 102        │ ALLOW → (S7comm)  │ ← Engineer programs PLC
│  5   │ Eng. WS         │ PLC-02          │ TCP 44818      │ ALLOW → (EtherNet/IP) ← Engineer programs PLC
│  6   │ OPC-UA Server   │ Historian DMZ   │ TCP 4840       │ ALLOW → (OPC-UA)  │ ← Data flows UP to historian
│  7   │ DMZ ANY         │ PLC ANY         │ TCP 502        │ DENY ✗            │ ← DMZ cannot control PLCs
│  8   │ IT ANY          │ PLC ANY         │ ANY            │ DENY ✗            │ ← IT cannot reach PLCs
│  9   │ ANY             │ SIS             │ ANY            │ DENY ✗ (except    │ ← SIS is ISOLATED
│      │                 │                 │                │  dedicated EWS)   │   hardened by design
│ 10   │ ANY             │ ANY             │ ANY            │ DENY ✗            │ ← Default deny
└──────────────────────────────────────────────────────────────────────────────┘

# ═══════════════════════════════════════════════════════════════
# SECUREBRIDGE SPECIFIC: PASSIVE TAP PORTS
# ═══════════════════════════════════════════════════════════════
#
# SecureBridge receives SPAN/mirror traffic — no active connection
# The managed OT switch (Cisco IE / Hirschmann) mirrors selected
# VLANs to SecureBridge monitoring interface

OT SWITCH SPAN CONFIGURATION (Cisco IE example):
┌─────────────────────────────────────────────────────────────────┐
│ monitor session 1 source vlan 20, 30              ← Mirror OT VLANs
│ monitor session 1 destination interface Gi1/1     ← To SecureBridge NIC
│                                                                   │
│ Note: SecureBridge NIC-2 is RECEIVE ONLY                         │
│       No IP address assigned to monitoring interface             │
│       Cannot initiate connections from monitoring NIC            │
└─────────────────────────────────────────────────────────────────┘

# What SecureBridge sees passively (no active connection):
┌─────────────────────────────────────────────────────────────────┐
│ Protocol  │ Port     │ What SecureBridge captures               │
├─────────────────────────────────────────────────────────────────┤
│ Modbus TCP│ TCP 502  │ All register reads/writes, device IDs   │
│ DNP3      │ TCP 20000│ Outstation responses, unsolicited msgs  │
│ OPC-UA    │ TCP 4840 │ Data subscriptions, node reads          │
│ S7comm    │ TCP 102  │ PLC programming sessions (flagged)      │
│ EtherNet/IP│TCP 44818│ Implicit/explicit messaging             │
│ Profibus  │ N/A      │ Via OPC-UA gateway translation          │
└─────────────────────────────────────────────────────────────────┘

# ═══════════════════════════════════════════════════════════════
# SECUREBRIDGE OUTBOUND PORTS SUMMARY
# (Only these ports allowed FROM SecureBridge to outside)
# ═══════════════════════════════════════════════════════════════

SECUREBRIDGE OUTBOUND (DMZ → IT Zone):
┌─────────────────────────────────────────────────────────────────┐
│ Port     │ Protocol │ Destination      │ Purpose               │
├─────────────────────────────────────────────────────────────────┤
│ TCP 8501 │ HTTP     │ SOC Console (IT) │ Streamlit dashboard   │
│ TCP 514  │ Syslog   │ SIEM (IT)        │ Security event logs   │
│ TCP 587  │ SMTP     │ Email Server     │ Alert emails          │
│ TCP 443  │ HTTPS    │ api.anthropic.com│ Claude LLM API        │
│ TCP 443  │ HTTPS    │ api.telegram.org │ Telegram bot alerts   │
└─────────────────────────────────────────────────────────────────┘

SECUREBRIDGE INBOUND (IT Zone → DMZ):
┌─────────────────────────────────────────────────────────────────┐
│ Port     │ Protocol │ Source           │ Purpose               │
├─────────────────────────────────────────────────────────────────┤
│ TCP 8501 │ HTTP     │ SOC Console only │ Dashboard access      │
│ TCP 22   │ SSH      │ Admin IPs only   │ Management access     │
└─────────────────────────────────────────────────────────────────┘

SECUREBRIDGE → OT (ALL DIRECTIONS):
┌─────────────────────────────────────────────────────────────────┐
│ DENY ALL ✗                                                       │
│ SecureBridge has NO active connection to OT devices             │
│ Monitoring is 100% passive via SPAN mirror only                 │
└─────────────────────────────────────────────────────────────────┘

# ═══════════════════════════════════════════════════════════════
# IEC 62443 ZONE AND CONDUIT MAPPING
# ═══════════════════════════════════════════════════════════════

Zone 1: Corporate IT (Level 4)
  Security Level: SL-1
  Conduit to DMZ: FW-02 (controlled, whitelisted)

Zone 2: Industrial DMZ (Level 3.5)
  Security Level: SL-2
  Contains: SecureBridge, Historian, Jump Server
  Conduit to OT: FW-03 + Data Diode (strict)

Zone 3: SCADA Zone (Level 2)
  Security Level: SL-2
  Conduit to Control: FW-03 (OT protocol aware)

Zone 4: Control Zone (Level 1)
  Security Level: SL-3
  Contains: PLCs, RTUs, DCS
  No inbound from IT/DMZ except engineering WS

Zone 5: Safety Zone (SIS)
  Security Level: SL-3 (air-gapped where possible)
  Dedicated Engineering Workstation only
  FULLY ISOLATED from all other zones

# ═══════════════════════════════════════════════════════════════
# INTERVIEW TALKING POINTS
# ═══════════════════════════════════════════════════════════════
#
# Q: "What ports does SecureBridge use to monitor OT?"
#
# A: "SecureBridge doesn't open any ports TO OT devices.
#    It receives a passive copy of OT traffic via a SPAN
#    mirror port on the managed switch — similar to how
#    Nozomi Networks operates. The monitoring NIC has no
#    IP address, so it physically cannot initiate connections.
#    SecureBridge only opens outbound ports from the DMZ
#    to the IT zone — specifically TCP 8501 for the dashboard,
#    TCP 514 for SIEM syslog, and TCP 443 for Claude API
#    and Telegram alerts. The OT network never receives
#    any traffic from SecureBridge."
#
# Q: "What if SecureBridge itself is compromised?"
#
# A: "The data diode is the answer. Even if an attacker
#    fully compromises SecureBridge, they cannot send
#    any traffic to OT devices because the data diode
#    is a hardware device that physically blocks reverse
#    flow. No software can override it. This is defense
#    in depth — SecureBridge being compromised is a
#    serious incident, but it cannot cascade into
#    OT device manipulation."
