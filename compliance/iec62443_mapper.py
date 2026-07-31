"""
IEC 62443 Compliance Mapper
Maps SecureBridge findings to IEC 62443 Security Requirements
Sandy Lukita | PT Optima Sarana Instrument
"""

# ─────────────────────────────────────────────
# IEC 62443 Security Requirements Database
# ─────────────────────────────────────────────

IEC62443_REQUIREMENTS = {
    "SR_1_1": {
        "code": "SR 1.1",
        "title": "Human User Identification and Authentication",
        "description": "The ICS shall provide the capability to identify and authenticate all human users.",
        "level": "SL-2",
        "category": "Identity Management"
    },
    "SR_1_2": {
        "code": "SR 1.2",
        "title": "Software Process and Device Identification",
        "description": "The ICS shall provide the capability to identify and authenticate all software processes and devices.",
        "level": "SL-2",
        "category": "Identity Management"
    },
    "SR_2_1": {
        "code": "SR 2.1",
        "title": "Authorization Enforcement",
        "description": "The ICS shall enforce authorizations assigned to all human users to control use of the ICS.",
        "level": "SL-2",
        "category": "Use Control"
    },
    "SR_3_1": {
        "code": "SR 3.1",
        "title": "Communication Integrity",
        "description": "The ICS shall provide the capability to ensure the integrity of transmitted information.",
        "level": "SL-2",
        "category": "System Integrity"
    },
    "SR_3_4": {
        "code": "SR 3.4",
        "title": "Software and Information Integrity",
        "description": "The ICS shall provide the capability to protect the integrity of software and information.",
        "level": "SL-2",
        "category": "System Integrity"
    },
    "SR_4_1": {
        "code": "SR 4.1",
        "title": "Information Confidentiality",
        "description": "The ICS shall provide the capability to protect the confidentiality of information in transit.",
        "level": "SL-2",
        "category": "Data Confidentiality"
    },
    "SR_5_1": {
        "code": "SR 5.1",
        "title": "Network Segmentation",
        "description": "The ICS shall provide the capability to segment the ICS into zones and conduits.",
        "level": "SL-2",
        "category": "Restricted Data Flow"
    },
    "SR_5_2": {
        "code": "SR 5.2",
        "title": "Zone Boundary Protection",
        "description": "The ICS shall provide the capability to monitor and control communications at zone boundaries.",
        "level": "SL-2",
        "category": "Restricted Data Flow"
    },
    "SR_6_1": {
        "code": "SR 6.1",
        "title": "Audit Log Accessibility",
        "description": "The ICS shall provide the capability to generate audit records for defined auditable events.",
        "level": "SL-2",
        "category": "Timely Response"
    },
    "SR_6_2": {
        "code": "SR 6.2",
        "title": "Continuous Monitoring",
        "description": "The ICS shall provide the capability to continuously monitor all security mechanisms.",
        "level": "SL-2",
        "category": "Timely Response"
    },
    "SR_7_3": {
        "code": "SR 7.3",
        "title": "Control System Backup",
        "description": "The ICS shall provide the capability to backup and restore the ICS including all necessary information.",
        "level": "SL-2",
        "category": "Resource Availability"
    },
    "SR_7_6": {
        "code": "SR 7.6",
        "title": "Network and Security Configuration Settings",
        "description": "The ICS shall provide the capability to provide and support the generation of documentation.",
        "level": "SL-2",
        "category": "Resource Availability"
    }
}

# ─────────────────────────────────────────────
# Vulnerability to IEC 62443 Mapping
# ─────────────────────────────────────────────

FINDING_TO_IEC = {
    "VULN_001_FLAT_NETWORK": {
        "title": "Flat IT/OT Network Architecture",
        "severity": "CRITICAL",
        "requirements": ["SR_5_1", "SR_5_2"],
        "status": "NON_COMPLIANT",
        "remediation": "Implement Purdue Model network segmentation with separate zones for IT, DMZ, and OT",
        "effort": "HIGH",
        "timeline": "4-6 weeks"
    },
    "VULN_002_WIFI_EXPOSED": {
        "title": "WiFi Credentials Physically Exposed",
        "severity": "CRITICAL",
        "requirements": ["SR_1_1", "SR_2_1"],
        "status": "NON_COMPLIANT",
        "remediation": "Change credentials immediately, implement WPA3 Enterprise, remove all visible passwords",
        "effort": "LOW",
        "timeline": "1 day"
    },
    "VULN_003_NO_OT_AUTH": {
        "title": "No Authentication on OT Devices",
        "severity": "CRITICAL",
        "requirements": ["SR_1_1", "SR_1_2", "SR_2_1"],
        "status": "NON_COMPLIANT",
        "remediation": "Implement device authentication where possible; use network-level controls where device auth is not supported",
        "effort": "MEDIUM",
        "timeline": "2-3 weeks"
    },
    "VULN_004_SPEAR_PHISHING": {
        "title": "Active Threat Actor — Spear Phishing",
        "severity": "CRITICAL",
        "requirements": ["SR_6_1", "SR_6_2"],
        "status": "NON_COMPLIANT",
        "remediation": "Email filtering, staff training, incident reporting procedure, threat investigation",
        "effort": "MEDIUM",
        "timeline": "1-2 weeks"
    },
    "VULN_005_UNPROTECTED_SERVER": {
        "title": "Single Unprotected Server",
        "severity": "CRITICAL",
        "requirements": ["SR_7_3", "SR_7_6"],
        "status": "NON_COMPLIANT",
        "remediation": "UPS installation, verified backup system with offsite copy, documented recovery procedure",
        "effort": "MEDIUM",
        "timeline": "1-2 weeks"
    },
    "VULN_006_NO_MONITORING": {
        "title": "No OT Security Monitoring",
        "severity": "HIGH",
        "requirements": ["SR_6_2"],
        "status": "NON_COMPLIANT",
        "remediation": "Deploy Nozomi Networks or Microsoft Defender for IoT for passive OT monitoring",
        "effort": "MEDIUM",
        "timeline": "1-2 weeks"
    },
    "VULN_007_ENGINEER_LAPTOPS": {
        "title": "Engineer Laptops on Client OT Networks",
        "severity": "HIGH",
        "requirements": ["SR_5_1", "SR_5_2", "SR_1_1"],
        "status": "NON_COMPLIANT",
        "remediation": "Implement hardened engineer laptops with MDM, endpoint protection, and network access controls",
        "effort": "MEDIUM",
        "timeline": "2-3 weeks"
    },
    "VULN_008_NO_PATCH_MGMT": {
        "title": "No Patch Management for OT Systems",
        "severity": "HIGH",
        "requirements": ["SR_7_6"],
        "status": "NON_COMPLIANT",
        "remediation": "Establish OT patch management process aligned with vendor recommendations and change management",
        "effort": "MEDIUM",
        "timeline": "Ongoing"
    },
    "VULN_009_NO_IRP": {
        "title": "No Incident Response Procedure",
        "severity": "HIGH",
        "requirements": ["SR_6_1", "SR_6_2"],
        "status": "NON_COMPLIANT",
        "remediation": "Develop and test OT-specific incident response plan with defined roles and escalation paths",
        "effort": "MEDIUM",
        "timeline": "2-3 weeks"
    },
    "VULN_010_NO_ASSET_INV": {
        "title": "No Asset Inventory",
        "severity": "MEDIUM",
        "requirements": ["SR_7_6"],
        "status": "NON_COMPLIANT",
        "remediation": "Complete IT and OT asset inventory using automated discovery tools",
        "effort": "LOW",
        "timeline": "1 week"
    },
    "VULN_011_WEAK_PASSWORD": {
        "title": "Weak Password Policy",
        "severity": "MEDIUM",
        "requirements": ["SR_1_1", "SR_2_1"],
        "status": "NON_COMPLIANT",
        "remediation": "Implement password policy: minimum 12 characters, complexity requirements, regular rotation",
        "effort": "LOW",
        "timeline": "1 week"
    },
    "VULN_012_NO_BACKUP_VERIFY": {
        "title": "No Backup Verification Process",
        "severity": "MEDIUM",
        "requirements": ["SR_7_3"],
        "status": "NON_COMPLIANT",
        "remediation": "Implement monthly backup restore test with documented results",
        "effort": "LOW",
        "timeline": "1 week"
    }
}

# ─────────────────────────────────────────────
# Remediation Progress Tracker
# ─────────────────────────────────────────────

REMEDIATION_STATUS = {
    "NOT_STARTED": {"label": "Belum Dimulai", "color": "red"},
    "IN_PROGRESS": {"label": "Sedang Berjalan", "color": "orange"},
    "COMPLETED": {"label": "Selesai", "color": "green"},
    "NON_COMPLIANT": {"label": "Tidak Patuh", "color": "red"},
    "PARTIAL": {"label": "Sebagian Patuh", "color": "orange"},
    "COMPLIANT": {"label": "Patuh", "color": "green"}
}


def calculate_compliance_score(findings: dict) -> dict:
    """
    Calculate overall IEC 62443 compliance score
    Returns score breakdown by category
    """
    total_requirements = len(IEC62443_REQUIREMENTS)
    compliant_count = 0
    partial_count = 0
    categories = {}

    for vuln_id, finding in findings.items():
        if finding.get("status") == "COMPLIANT":
            compliant_count += len(finding.get("requirements", []))
        elif finding.get("status") == "PARTIAL":
            partial_count += len(finding.get("requirements", []))

        # Group by category
        for req_id in finding.get("requirements", []):
            req = IEC62443_REQUIREMENTS.get(req_id, {})
            category = req.get("category", "Other")
            if category not in categories:
                categories[category] = {
                    "total": 0,
                    "compliant": 0,
                    "status": finding.get("status")
                }
            categories[category]["total"] += 1
            if finding.get("status") == "COMPLIANT":
                categories[category]["compliant"] += 1

    # Overall score
    score = (compliant_count / (total_requirements * 2)) * 100
    score = max(0, min(100, score))

    # Determine security level achieved
    if score >= 80:
        security_level = "SL-2 (Target)"
    elif score >= 60:
        security_level = "SL-1 (Basic)"
    elif score >= 40:
        security_level = "SL-0 (Partial)"
    else:
        security_level = "Non-Compliant"

    return {
        "overall_score": round(score, 1),
        "security_level": security_level,
        "compliant_requirements": compliant_count,
        "total_requirements": total_requirements,
        "categories": categories
    }


def get_priority_findings(findings: dict) -> list:
    """Return findings sorted by severity and effort"""
    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    effort_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

    sorted_findings = sorted(
        findings.items(),
        key=lambda x: (
            priority_order.get(x[1].get("severity", "LOW"), 3),
            effort_order.get(x[1].get("effort", "HIGH"), 2)
        )
    )
    return sorted_findings
